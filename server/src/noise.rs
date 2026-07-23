use anyhow::Result;
use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct NoiseHandler {
    sk_server: StaticSecret,
    pk_server: PublicKey,
}

impl NoiseHandler {
    pub fn new(sk_server: StaticSecret) -> Self {
        let pk_server = PublicKey::from(&sk_server);
        Self { sk_server, pk_server }
    }

    pub fn pk_server_bytes(&self) -> [u8; 32] {
        self.pk_server.to_bytes()
    }

    pub async fn handshake(
        &self,
        stream: &mut TcpStream,
        prologue: &[u8],
    ) -> Result<TransportState> {
        let pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid noise pattern: {:?}", e))?;

        let sk_bytes = self.sk_server.to_bytes();
        let builder = Builder::new(pattern)
            .prologue(prologue)?
            .local_private_key(&sk_bytes)?;

        let mut handshake = builder.build_responder()?;

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        handshake.read_message(&buf[..n], &mut [])?;

        let mut msg2 = [0u8; 4096];
        let len = handshake.write_message(&[], &mut msg2)?;
        stream.write_all(&msg2[..len]).await?;

        let transport = handshake.into_transport_mode()?;
        Ok(transport)
    }
}
