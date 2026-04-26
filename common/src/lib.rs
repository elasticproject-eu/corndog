use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Simplified Network Utilities

pub async fn send_file(stream: &mut TcpStream, filename: &str, data: &[u8]) -> Result<()> {
    stream.write_u32(filename.len() as u32).await?;
    stream.write_all(filename.as_bytes()).await?;

    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;

    stream.flush().await?;

    Ok(())
} 

pub async fn receive_file(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let filename_len = stream.read_u32().await? as usize;
    let mut filename_buf = vec![0u8; filename_len];
    
    stream.read_exact(&mut filename_buf).await?;
    let filename = String::from_utf8(filename_buf)?;
    
    let data_len = stream.read_u32().await? as usize;
    let mut data = vec![0u8; data_len];
    stream.read_exact(&mut data).await?;
    
    Ok((filename, data))
}

pub async fn send_bytes(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;

    stream.flush().await?;

    Ok(())
}

pub async fn receive_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    
    Ok(buf)
}

pub fn compute_file_hash(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}