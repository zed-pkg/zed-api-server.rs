//! Small reusable seams for the non-admin API server; owner contracts remain authoritative.
use async_trait::async_trait;
pub const ORES_MW_CONFIG:&str=include_str!("../../.ores-mw.toml");
pub const ORES_RATE_LIMIT_CONFIG:&str=include_str!("../../.ores-rl.toml");
pub const ORES_LRU_CONFIG:&str=include_str!("../../.ores-lru.toml");
pub const SHARED_AUTH_CONFIG:&str=include_str!("../../.shared-auth.toml");
#[derive(Debug)] pub struct ContractSyntax{pub middleware:toml::Value,pub rate_limit:toml::Value,pub lru:toml::Value,pub shared_auth:toml::Value}
pub fn parse_contract_syntax()->Result<ContractSyntax,toml::de::Error>{Ok(ContractSyntax{middleware:toml::from_str(ORES_MW_CONFIG)?,rate_limit:toml::from_str(ORES_RATE_LIMIT_CONFIG)?,lru:toml::from_str(ORES_LRU_CONFIG)?,shared_auth:toml::from_str(SHARED_AUTH_CONFIG)?})}
#[async_trait] pub trait MiddlewarePort<Request:Send+'static,Response:Send+'static>:Send+Sync{type Error:Send+Sync+'static;async fn call(&self,request:Request)->Result<Response,Self::Error>;}
#[async_trait] pub trait SharedAuthPort<Credential:Send+'static,Principal:Send+'static>:Send+Sync{type Error:Send+Sync+'static;async fn authenticate(&self,credential:Credential)->Result<Principal,Self::Error>;}
#[async_trait] pub trait RateLimitPort<Key:Send+'static,Decision:Send+'static>:Send+Sync{type Error:Send+Sync+'static;async fn evaluate(&self,key:Key)->Result<Decision,Self::Error>;}
#[async_trait] pub trait CachePort<Key:Send+Sync+'static,Value:Send+'static>:Send+Sync{type Error:Send+Sync+'static;async fn get(&self,key:&Key)->Result<Option<Value>,Self::Error>;async fn put(&self,key:Key,value:Value)->Result<(),Self::Error>;}
#[cfg(test)]mod tests{use super::*;#[test]fn embedded_owner_configs_are_valid_toml(){parse_contract_syntax().expect("consumer contract TOML must parse");}}
