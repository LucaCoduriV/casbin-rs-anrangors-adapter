use crate::CasbinRule;
use arangors::uclient::ClientExt;
use arangors::{AqlQuery, Database};
use async_trait::async_trait;
use casbin::{error::AdapterError, Result};

#[async_trait]
pub(crate) trait CasbinDao {
    async fn save_policy(&self, rules: Vec<CasbinRule>) -> Result<()>;
    async fn clear_policy(&self) -> Result<()>;
    async fn load_policy(&self) -> Result<Vec<CasbinRule>>;
    async fn add_policy(&self, rule: CasbinRule) -> Result<bool>;
    async fn add_policies(&self, rules: Vec<CasbinRule>) -> Result<bool>;
    async fn remove_policy(&self, pt: &str, rule: Vec<String>) -> Result<bool>;
    async fn remove_policies(&self, pt: &str, rules: Vec<Vec<String>>) -> Result<bool>;
    async fn remove_filtered_policy(
        &self,
        pt: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool>;
}

#[async_trait]
impl<T: ClientExt + Send> CasbinDao for Database<T> {
    async fn save_policy(&self, rules: Vec<CasbinRule>) -> Result<()> {
        let json = serde_json::value::to_value(&rules).unwrap();

        let aql = AqlQuery::builder()
            .query("FOR r IN @rules INSERT r IN casbin")
            .bind_var("rules", json)
            .build();

        let _: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(())
    }

    async fn clear_policy(&self) -> Result<()> {
        let aql = AqlQuery::builder()
            .query("FOR r IN casbin REMOVE r IN casbin")
            .build();

        let _: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(())
    }

    async fn load_policy(&self) -> Result<Vec<CasbinRule>> {
        let aql = AqlQuery::builder()
            .query("FOR r IN casbin RETURN r")
            .build();

        let rules: Vec<CasbinRule> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(rules)
    }

    async fn add_policy(&self, rule: CasbinRule) -> Result<bool> {
        let json = serde_json::value::to_value(&rule).unwrap();

        let aql = AqlQuery::builder()
            .query("INSERT @rule IN casbin")
            .bind_var("rule", json)
            .build();

        let _: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(true)
    }

    async fn add_policies(&self, rules: Vec<CasbinRule>) -> Result<bool> {
        let json = serde_json::value::to_value(&rules).unwrap();

        let aql = AqlQuery::builder()
            .query("FOR r IN @rules INSERT r IN casbin")
            .bind_var("rules", json)
            .build();

        let _: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(true)
    }

    async fn remove_policy(&self, pt: &str, rule: Vec<String>) -> Result<bool> {
        let rule = normalize_casbin_rule(rule, 0);

        let aql = AqlQuery::builder()
            .query(
                r#"FOR r IN casbin
    FILTER r.ptype == @ptype
    FILTER r.v0 == @v0
    FILTER r.v1 == @v1
    FILTER r.v2 == @v2
    FILTER r.v3 == @v3
    FILTER r.v4 == @v4
    FILTER r.v5 == @v5
    REMOVE r IN casbin
    RETURN 1"#,
            )
            .bind_var("ptype", pt)
            .bind_var("v0", rule[0].as_str())
            .bind_var("v1", rule[1].as_str())
            .bind_var("v2", rule[2].as_str())
            .bind_var("v3", rule[3].as_str())
            .bind_var("v4", rule[4].as_str())
            .bind_var("v5", rule[5].as_str())
            .build();

        let arr: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;

        Ok(!arr.is_empty())
    }

    async fn remove_policies(&self, pt: &str, rules: Vec<Vec<String>>) -> Result<bool> {
        for rule in rules {
            self.remove_policy(pt, rule).await?;
        }

        Ok(true)
    }

    async fn remove_filtered_policy(&self, pt: &str, field_index: usize, field_values: Vec<String>)
        -> Result<bool> {
        let field_values = normalize_casbin_rule(field_values, field_index);

        let aql = if field_index == 5 {
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v5 == NOT_NULL(@f0, r.v5)
            REMOVE r IN casbin
            RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .build()
        }else if field_index == 4 {
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v4 == NOT_NULL(@f0, r.v4)
            FILTER r.v5 == NOT_NULL(@f1, r.v5)
            REMOVE r IN casbin
            RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .bind_var("f1", if field_values[1].is_empty() { None } else { Some(field_values[1].as_str()) })
                .build()
        }else if field_index == 3 {
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v3 == NOT_NULL(@f0, r.v3)
            FILTER r.v4 == NOT_NULL(@f1, r.v4)
            FILTER r.v5 == NOT_NULL(@f2, r.v5)
            REMOVE r IN casbin
            RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .bind_var("f1", if field_values[1].is_empty() { None } else { Some(field_values[1].as_str()) })
                .bind_var("f2", if field_values[2].is_empty() { None } else { Some(field_values[2].as_str()) })
                .build()
        }else if field_index == 2{
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v2 == NOT_NULL(@f0, r.v2)
            FILTER r.v3 == NOT_NULL(@f1, r.v3)
            FILTER r.v4 == NOT_NULL(@f2, r.v4)
            FILTER r.v5 == NOT_NULL(@f3, r.v5)
            REMOVE r IN casbin
            RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .bind_var("f1", if field_values[1].is_empty() { None } else { Some(field_values[1].as_str()) })
                .bind_var("f2", if field_values[2].is_empty() { None } else { Some(field_values[2].as_str()) })
                .bind_var("f3", if field_values[3].is_empty() { None } else { Some(field_values[3].as_str()) })
                .build()
        }else if field_index == 1{
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v1 == NOT_NULL(@f0, r.v1)
            FILTER r.v2 == NOT_NULL(@f1, r.v2)
            FILTER r.v3 == NOT_NULL(@f2, r.v3)
            FILTER r.v4 == NOT_NULL(@f3, r.v4)
            FILTER r.v5 == NOT_NULL(@f4, r.v5)
            REMOVE r IN casbin
            RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .bind_var("f1", if field_values[1].is_empty() { None } else { Some(field_values[1].as_str()) })
                .bind_var("f2", if field_values[2].is_empty() { None } else { Some(field_values[2].as_str()) })
                .bind_var("f3", if field_values[3].is_empty() { None } else { Some(field_values[3].as_str()) })
                .bind_var("f4", if field_values[4].is_empty() { None } else { Some(field_values[4].as_str()) })
                .build()
        }else{
            AqlQuery::builder()
                .query(r#"FOR r IN casbin
            FILTER r.ptype == @ptype
            FILTER r.v0 == NOT_NULL(@f0, r.v0)
            FILTER r.v1 == NOT_NULL(@f1, r.v1)
            FILTER r.v2 == NOT_NULL(@f2, r.v2)
            FILTER r.v3 == NOT_NULL(@f3, r.v3)
            FILTER r.v4 == NOT_NULL(@f4, r.v4)
            FILTER r.v5 == NOT_NULL(@f5, r.v5)
            REMOVE r IN casbin
                RETURN 1"#)
                .bind_var("ptype", pt)
                .bind_var("f0", if field_values[0].is_empty() { None } else { Some(field_values[0].as_str()) })
                .bind_var("f1", if field_values[1].is_empty() { None } else { Some(field_values[1].as_str()) })
                .bind_var("f2", if field_values[2].is_empty() { None } else { Some(field_values[2].as_str()) })
                .bind_var("f3", if field_values[3].is_empty() { None } else { Some(field_values[3].as_str()) })
                .bind_var("f4", if field_values[4].is_empty() { None } else { Some(field_values[4].as_str()) })
                .bind_var("f5", if field_values[5].is_empty() { None } else { Some(field_values[5].as_str()) })
                .build()
        };

        let arr: Vec<serde_json::value::Value> = self
            .aql_query(aql)
            .await
            .map_err(|e| AdapterError(Box::new(e)))?;
        Ok(!arr.is_empty())
    }
}

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}
