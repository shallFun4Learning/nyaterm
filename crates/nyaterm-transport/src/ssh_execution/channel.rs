use crate::{SshClientHandler, SshMultiplexHandle};
use russh::{Channel, client};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

pub(super) struct ExecChannel {
    channel: Option<Channel<client::Msg>>,
    runtime: Handle,
}

impl ExecChannel {
    pub(super) async fn open(handle: &client::Handle<SshClientHandler>) -> anyhow::Result<Self> {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|error| anyhow::anyhow!("failed to open exec channel: {error}"))?;
        Ok(Self {
            channel: Some(channel),
            runtime: Handle::current(),
        })
    }

    pub(super) async fn open_shared(multiplex: &SshMultiplexHandle) -> anyhow::Result<Self> {
        let handle = multiplex.exec_target_handle().await.lock_owned().await;
        let mut closed = multiplex.inner.closed.subscribe();
        let (send, receive) = oneshot::channel();
        multiplex.inner.runtime.spawn(async move {
            if send.is_closed() {
                return;
            }
            let result = tokio::select! {
                biased;
                _ = closed.wait_for(|closed| *closed) => {
                    Err(anyhow::anyhow!("SSH multiplex handle is closed"))
                }
                result = Self::open(&handle) => result,
            };
            drop(handle);
            let _ = send.send(result);
        });
        receive
            .await
            .map_err(|_| anyhow::anyhow!("SSH exec channel open stopped"))?
    }

    pub(super) fn channel(&mut self) -> &mut Channel<client::Msg> {
        self.channel.as_mut().expect("open exec channel")
    }

    pub(super) async fn request(&mut self, command: Vec<u8>) -> anyhow::Result<()> {
        self.channel()
            .exec(true, command)
            .await
            .map_err(|error| anyhow::anyhow!("failed to execute remote command: {error}"))
    }

    pub(super) async fn close(mut self) {
        let _ = self.channel().close().await;
        self.channel = None;
    }
}

impl Drop for ExecChannel {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.take() {
            let (reader, writer) = channel.split();
            drop(reader);
            self.runtime.spawn(async move {
                let _ = writer.close().await;
            });
        }
    }
}
