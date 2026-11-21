//! SSH command execution, cancellation, and runtime adapters.
mod channel;
pub mod streaming;
pub mod sudo;

use self::channel::ExecChannel;
use crate::{SshMultiplexHandle, SshSessionConfig, open_authenticated_ssh_handle};
use russh::{ChannelMsg, Disconnect};
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("SSH exec request was rejected")]
pub struct ExecRequestDenied;

/// Common command execution for services that do not own SSH connections.
#[derive(Clone, Debug)]
pub struct SshExecService {
    config: SshSessionConfig,
    multiplex: Option<SshMultiplexHandle>,
}

impl SshExecService {
    pub fn new(config: SshSessionConfig) -> Self {
        Self {
            config,
            multiplex: None,
        }
    }

    pub fn with_multiplex(
        config: SshSessionConfig,
        multiplex: SshMultiplexHandle,
    ) -> anyhow::Result<Self> {
        multiplex.ensure_matches_config(&config)?;
        Ok(Self {
            config,
            multiplex: Some(multiplex),
        })
    }

    pub fn run_command(
        &self,
        command: impl AsRef<str>,
        timeout: Duration,
    ) -> anyhow::Result<RemoteCommandOutput> {
        run_ssh_command(
            self.config.clone(),
            self.multiplex.clone(),
            command.as_ref().as_bytes().to_vec(),
            timeout,
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<u32>,
}

pub fn run_local_command(
    command: impl AsRef<str>,
    cwd: Option<PathBuf>,
    timeout: Duration,
) -> anyhow::Result<RemoteCommandOutput> {
    let command = command.as_ref().to_string();
    run_ssh_exec_operation(async move {
        tokio::time::timeout(timeout, async move {
            let mut child = local_shell_command(&command);
            if let Some(cwd) = cwd.filter(|value| !value.as_os_str().is_empty()) {
                child.current_dir(cwd);
            }
            child.kill_on_drop(true);
            child.stdout(Stdio::piped());
            child.stderr(Stdio::piped());
            let output = child
                .output()
                .await
                .map_err(|error| anyhow::anyhow!("failed to run local command: {error}"))?;
            Ok(RemoteCommandOutput {
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_status: output
                    .status
                    .code()
                    .and_then(|code| u32::try_from(code).ok()),
            })
        })
        .await
        .map_err(|_| anyhow::anyhow!("local command timed out"))?
    })
}

#[cfg(windows)]
fn local_shell_command(command: &str) -> tokio::process::Command {
    let mut child = tokio::process::Command::new("cmd");
    child.args(["/C", command]);
    child
}

#[cfg(not(windows))]
fn local_shell_command(command: &str) -> tokio::process::Command {
    let mut child = tokio::process::Command::new("sh");
    child.args(["-lc", command]);
    child
}
pub fn run_ssh_exec_operation<T, F>(operation: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("nyaterm-ssh-exec")
        .build()
        .map_err(|error| anyhow::anyhow!("failed to start SSH exec runtime: {error}"))?;
    runtime.block_on(operation)
}

pub async fn exec_ssh_command(
    config: SshSessionConfig,
    command: Vec<u8>,
    timeout: Duration,
) -> anyhow::Result<RemoteCommandOutput> {
    tokio::time::timeout(timeout, async move {
        config.ensure_shell_available()?;
        let (handle, jump_handles) = open_authenticated_ssh_handle(&config).await?;
        let mut channel = ExecChannel::open(&handle).await?;
        channel.request(command).await?;
        let output = collect_exec_channel(channel).await?;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "ssh exec completed", "en")
            .await;
        for jump_handle in jump_handles {
            let _ = jump_handle
                .disconnect(Disconnect::ByApplication, "ssh exec completed", "en")
                .await;
        }

        Ok(output)
    })
    .await
    .map_err(|_| anyhow::anyhow!("remote command timed out"))?
}

pub fn run_ssh_command(
    config: SshSessionConfig,
    multiplex: Option<SshMultiplexHandle>,
    command: Vec<u8>,
    timeout: Duration,
) -> anyhow::Result<RemoteCommandOutput> {
    config.ensure_shell_available()?;
    if let Some(multiplex) = multiplex {
        multiplex.ensure_matches_config(&config)?;
        return multiplex.block_on(exec_ssh_command_with_multiplex(
            config,
            multiplex.clone(),
            command,
            timeout,
        ));
    }
    run_ssh_exec_operation(exec_ssh_command(config, command, timeout))
}

/// Execute a command with a separate stdin payload; secrets never enter argv.
pub fn run_ssh_command_with_input(
    config: SshSessionConfig,
    multiplex: Option<SshMultiplexHandle>,
    command: String,
    input: Option<nyaterm_core::SecretString>,
    timeout: Duration,
) -> anyhow::Result<RemoteCommandOutput> {
    config.ensure_shell_available()?;
    let attempt = multiplex
        .as_ref()
        .map(|m| &m.inner.attempt)
        .unwrap_or(&config.attempt)
        .clone();
    attempt.ensure_shell_available()?;
    let runtime_owner = multiplex.clone();
    let operation = async move {
        config
            .attempt
            .until_cancelled(tokio::time::timeout(timeout, async {
                let (mut channel, owned) = if let Some(multiplex) = multiplex.as_ref() {
                    (ExecChannel::open_shared(multiplex).await?, None)
                } else {
                    let (handle, jumps) = open_authenticated_ssh_handle(&config).await?;
                    let channel = ExecChannel::open(&handle).await?;
                    (channel, Some((handle, jumps)))
                };
                channel.request(command.into_bytes()).await?;
                if let Some(secret) = input {
                    let bytes = zeroize::Zeroizing::new(
                        format!("{}\n", secret.expose_secret()).into_bytes(),
                    );
                    channel.channel().data(&bytes[..]).await?;
                }
                channel.channel().eof().await?;
                let output = collect_exec_channel(channel).await;
                if let Some((handle, jumps)) = owned {
                    let _ = handle
                        .disconnect(Disconnect::ByApplication, "command completed", "en")
                        .await;
                    for jump in jumps {
                        let _ = jump
                            .disconnect(Disconnect::ByApplication, "command completed", "en")
                            .await;
                    }
                }
                output
            }))
            .await
            .map_err(anyhow::Error::msg)?
            .map_err(|_| anyhow::anyhow!("remote command timed out"))?
    };
    if let Some(multiplex) = runtime_owner.as_ref() {
        multiplex.block_on(operation)
    } else {
        run_ssh_exec_operation(operation)
    }
}

pub async fn exec_ssh_command_with_multiplex(
    config: SshSessionConfig,
    multiplex: SshMultiplexHandle,
    command: Vec<u8>,
    timeout: Duration,
) -> anyhow::Result<RemoteCommandOutput> {
    tokio::time::timeout(timeout, async move {
        config.ensure_shell_available()?;
        multiplex.inner.attempt.ensure_shell_available()?;
        let mut channel = ExecChannel::open_shared(&multiplex).await?;
        channel.request(command).await?;
        collect_exec_channel(channel).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("remote command timed out"))?
}

async fn collect_exec_channel(mut channel: ExecChannel) -> anyhow::Result<RemoteCommandOutput> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_status = None;
    let mut eof_seen = false;
    loop {
        match channel.channel().wait().await {
            Some(ChannelMsg::Success) => {}
            Some(ChannelMsg::Failure) => {
                channel.close().await;
                return Err(ExecRequestDenied.into());
            }
            Some(ChannelMsg::Data { data }) => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                stderr.push_str(&String::from_utf8_lossy(&data));
            }
            Some(ChannelMsg::ExitStatus {
                exit_status: status,
            }) => {
                exit_status = Some(status);
            }
            Some(ChannelMsg::Eof) => eof_seen = true,
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
        // EOF alone is not process-exit evidence; exit status can arrive later.
        if eof_seen && exit_status.is_some() {
            break;
        }
    }

    channel.close().await;
    Ok(RemoteCommandOutput {
        stdout,
        stderr,
        exit_status,
    })
}

pub fn ensure_remote_command_success(
    output: RemoteCommandOutput,
    context: &str,
) -> anyhow::Result<RemoteCommandOutput> {
    if matches!(output.exit_status, Some(0) | None) {
        return Ok(output);
    }

    let stderr = output.stderr.trim();
    let stdout = output.stdout.trim();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "remote command failed"
    };

    anyhow::bail!("{context}: {detail}")
}
