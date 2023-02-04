use std::sync::{Arc, Mutex};
use arangors::Database;
use arangors::uclient::ClientExt;
use casbin::{Adapter, Filter, Model};
use async_trait::async_trait;
use tokio::task::spawn_blocking;
use crate::model::CasbinRule;
use casbin_dao::CasbinDao;

mod model;
mod casbin_dao;

#[cfg(test)]
mod lib_test;

pub struct ArangorsAdapter<C: ClientExt> {
    database: Database<C>
}

impl<C: ClientExt> ArangorsAdapter<C> {
    pub fn new(database: Database<C>) -> Self {
        Self {
            database
        }
    }
}
#[async_trait]
impl<C: ClientExt + Send> Adapter for ArangorsAdapter<C> {
    async fn load_policy(&self, m: &mut dyn Model) -> casbin::Result<()> {

        let rules = self.database.load_policy().await?;

        for casbin_rule in &rules {
            let rule = load_policy_line(casbin_rule);

            if let Some(ref sec) = casbin_rule.ptype.chars().next().map(|x| x.to_string()) {
                if let Some(t1) = m.get_mut_model().get_mut(sec) {
                    if let Some(t2) = t1.get_mut(&casbin_rule.ptype) {
                        if let Some(rule) = rule {
                            t2.get_mut_policy().insert(rule);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> casbin::Result<()> {
        unimplemented!()
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> casbin::Result<()> {
        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x: &Vec<String>| map_to_casbin_rule(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x: &Vec<String>| map_to_casbin_rule(ptype, x));

                rules.extend(new_rules);
            }
        }

        self.database.save_policy(rules).await
    }

    async fn clear_policy(&mut self) -> casbin::Result<()> {
        self.database.clear_policy().await
    }

    fn is_filtered(&self) -> bool {
        false
    }

    async fn add_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> casbin::Result<bool> {
        let ptype_c = ptype.to_string();

        if let Some(new_rule) = map_to_casbin_rule(&ptype_c, &rule) {
            return self.database.add_policy(new_rule).await;
        }
        Ok(false)
    }

    async fn add_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> casbin::Result<bool> {
        let ptype_c = ptype.to_string();

        let new_rules = rules
            .iter()
            .filter_map(|x: &Vec<String>| map_to_casbin_rule(&ptype_c, x))
            .collect::<Vec<CasbinRule>>();

        return self.database.add_policies(new_rules).await;
    }

    async fn remove_policy(&mut self, sec: &str, ptype: &str, rule: Vec<String>) -> casbin::Result<bool> {
        let ptype_c = ptype.to_string();
        let v = self.database.remove_policy(&ptype_c, rule).await;
        println!("{v:?}");
        v
    }

    async fn remove_policies(&mut self, sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> casbin::Result<bool> {
        let ptype_c = ptype.to_string();
        self.database.remove_policies(&ptype_c, rules).await
    }

    async fn remove_filtered_policy(&mut self, sec: &str, ptype: &str, field_index: usize, field_values: Vec<String>) -> casbin::Result<bool> {
        unimplemented!()
    }
}

fn map_to_casbin_rule(ptype: &str, rule: &[String]) -> Option<CasbinRule>{
    if ptype.trim().is_empty() || rule.is_empty() {
        return None;
    }

    let new_rule = CasbinRule{
        _key: None,
        ptype: ptype.to_owned(),
        v0: rule[0].to_owned(),
        v1: rule.get(1).map(String::to_owned).unwrap_or(String::from("")),
        v2: rule.get(2).map(String::to_owned).unwrap_or(String::from("")),
        v3: rule.get(3).map(String::to_owned).unwrap_or(String::from("")),
        v4: rule.get(4).map(String::to_owned).unwrap_or(String::from("")),
        v5: rule.get(5).map(String::to_owned).unwrap_or(String::from("")),
    };

    Some(new_rule)
}

fn load_policy_line(casbin_rule: &CasbinRule) -> Option<Vec<String>> {
    if casbin_rule.ptype.chars().next().is_some() {
        return normalize_policy(casbin_rule);
    }

    None
}

fn normalize_policy(casbin_rule: &CasbinRule) -> Option<Vec<String>> {
    let mut result = vec![
        &casbin_rule.v0,
        &casbin_rule.v1,
        &casbin_rule.v2,
        &casbin_rule.v3,
        &casbin_rule.v4,
        &casbin_rule.v5,
    ];

    while let Some(last) = result.last() {
        if last.is_empty() {
            result.pop();
        } else {
            break;
        }
    }

    if !result.is_empty() {
        return Some(result.iter().map(|&x| x.to_owned()).collect());
    }

    None
}