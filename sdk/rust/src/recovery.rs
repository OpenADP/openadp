use crate::keygen::recover_encryption_key;
use crate::{Identity, ServerInfo, Result, AuthCodes};

pub async fn recover_encryption_key_with_server_info(
    identity: &Identity,
    password: &str,
    server_infos: Vec<ServerInfo>,
    threshold: usize,
    auth_codes: AuthCodes,
) -> Result<crate::RecoverEncryptionKeyResult> {
    match recover_encryption_key(&identity, &password, server_infos, threshold, auth_codes).await {
        Ok(result) => Ok(result),
        Err(e) => Err(e),
    }
} 