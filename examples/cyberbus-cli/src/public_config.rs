//! Snapshot only successful SDK public-profile results, never ClientConfig or store.
use crate::{example, local_error, pb};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

pub(super) const METHOD: &str = "cyberbus.example.v1.Echo/GetPublicConfig";
pub(super) const REQUEST: &str = "type.googleapis.com/cyberbus.example.v1.GetPublicConfigRequest";
pub(super) const RESPONSE: &str = "type.googleapis.com/cyberbus.example.v1.GetPublicConfigReply";
const CONFIG_TYPE: &str = "type.googleapis.com/cyberbus.example.v1.PublicConfig";
pub(super) type Profile = Arc<Mutex<Option<pb::PublicProfile>>>;

fn config(profile: &pb::PublicProfile) -> Result<example::PublicConfig, pb::ProtocolError> {
    let value = profile
        .public_config
        .as_ref()
        .ok_or_else(|| local_error(pb::ErrorCode::NotFound, "public configuration not declared"))?;
    if value.type_url != CONFIG_TYPE {
        return Err(local_error(
            pb::ErrorCode::TypeMismatch,
            "public configuration type",
        ));
    }
    example::PublicConfig::decode(value.value.as_slice())
        .map_err(|_| local_error(pb::ErrorCode::TypeMismatch, "invalid public configuration"))
}

pub(super) fn accept(
    profile: pb::PublicProfile,
    state: &Profile,
    revision: &mut u64,
) -> Result<(), String> {
    let config = config(&profile).map_err(|e| crate::protocol_error(&e))?;
    println!(
        "PUBLIC_PROFILE revision={} name={:?} application_version={:?} semantic_version={:?} config_sha256={}",
        profile.config_revision, profile.device_name, config.application_version,
        profile.config_semantic_version, hex::encode(Sha256::digest(config.encode_to_vec()))
    );
    *revision = profile.config_revision;
    *state.lock().unwrap() = Some(profile);
    Ok(())
}

pub(super) fn reply(state: &Profile, bytes: &[u8]) -> Result<Vec<u8>, pb::ProtocolError> {
    let request = example::GetPublicConfigRequest::decode(bytes)
        .map_err(|_| local_error(pb::ErrorCode::TypeMismatch, "invalid configuration request"))?;
    if request.request_id.len() != 16 {
        return Err(local_error(
            pb::ErrorCode::InvalidArgument,
            "configuration request ID",
        ));
    }
    let profile = state.lock().unwrap();
    let profile = profile
        .as_ref()
        .ok_or_else(|| local_error(pb::ErrorCode::NotFound, "public profile not declared"))?;
    Ok(example::GetPublicConfigReply {
        request_id: request.request_id,
        public_config: Some(config(profile)?),
        device_name: profile.device_name.clone(),
        config_semantic_version: profile.config_semantic_version.clone(),
        config_revision: profile.config_revision,
    }
    .encode_to_vec())
}

pub(super) fn decode_reply(
    bytes: &[u8],
    request_id: &[u8],
) -> Result<example::GetPublicConfigReply, pb::ProtocolError> {
    let reply = example::GetPublicConfigReply::decode(bytes)
        .map_err(|_| local_error(pb::ErrorCode::TypeMismatch, "invalid configuration reply"))?;
    if request_id.len() != 16
        || reply.request_id != request_id
        || reply.public_config.is_none()
        || reply.config_revision == 0
        || reply.config_semantic_version.is_empty()
    {
        return Err(local_error(
            pb::ErrorCode::ProtocolError,
            "configuration reply mismatch",
        ));
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(name: &str, version: &str, revision: u64) -> pb::PublicProfile {
        pb::PublicProfile {
            device_name: name.into(),
            config_revision: revision,
            config_semantic_version: "1.0.0".into(),
            public_config: Some(prost_types::Any {
                type_url: CONFIG_TYPE.into(),
                value: example::PublicConfig {
                    application_version: version.into(),
                }
                .encode_to_vec(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn config_rpc_returns_latest_accepted_public_declaration() {
        let state = Profile::default();
        let mut revision = 0;
        let request_id = vec![7; 16];
        let request = example::GetPublicConfigRequest {
            request_id: request_id.clone(),
        }
        .encode_to_vec();
        assert_eq!(
            reply(&state, &request).unwrap_err().code,
            pb::ErrorCode::NotFound as i32
        );
        for (name, version, expected_revision) in [("first", "2.4.0", 3), ("changed", "2.5.0", 8)] {
            accept(
                declaration(name, version, expected_revision),
                &state,
                &mut revision,
            )
            .unwrap();
            let response = decode_reply(&reply(&state, &request).unwrap(), &request_id).unwrap();
            assert_eq!(response.device_name, name);
            assert_eq!(response.public_config.unwrap().application_version, version);
            assert_eq!(response.config_revision, expected_revision);
            assert_eq!(revision, expected_revision);
        }
    }

    #[test]
    fn config_rpc_rejects_wrong_correlation_missing_config_and_wrong_public_type() {
        let state = Profile::default();
        let mut revision = 0;
        accept(declaration("public", "1.0.0", 1), &state, &mut revision).unwrap();
        let request_id = vec![8; 16];
        let request = example::GetPublicConfigRequest {
            request_id: request_id.clone(),
        }
        .encode_to_vec();
        let bytes = reply(&state, &request).unwrap();
        assert!(decode_reply(&bytes, &[9; 16]).is_err());
        let mut response = decode_reply(&bytes, &request_id).unwrap();
        response.public_config = None;
        assert!(decode_reply(&response.encode_to_vec(), &request_id).is_err());
        let invalid = example::GetPublicConfigRequest {
            request_id: vec![1; 15],
        }
        .encode_to_vec();
        assert_eq!(
            reply(&state, &invalid).unwrap_err().code,
            pb::ErrorCode::InvalidArgument as i32
        );
        state
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .public_config
            .as_mut()
            .unwrap()
            .type_url = "private/config".into();
        assert_eq!(
            reply(&state, &request).unwrap_err().code,
            pb::ErrorCode::TypeMismatch as i32
        );
    }
}
