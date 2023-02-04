use super::*;

fn to_owned(v: Vec<&str>) -> Vec<String> {
    v.into_iter().map(|x| x.to_owned()).collect()
}

#[tokio::test]
async fn test_adapter() {
    use casbin::prelude::*;

    let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

    let m = DefaultModel::from_file("examples/rbac_model.conf")
        .await
        .unwrap();

    let mut e = Enforcer::new(m, file_adapter).await.unwrap();

    let conn = arangors::Connection::establish_jwt(
        "http://localhost:8529",
        "root",
        "root",
    ).await.unwrap();

    let db = conn.db("_system").await.unwrap();

    let mut adapter = ArangorsAdapter::new(db);

    assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_ok());

    assert!(adapter
        .add_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .add_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
        .await
        .is_ok());
    assert!(adapter
        .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
        .await
        .is_ok());

    assert!(adapter
        .remove_policies(
            "",
            "p",
            vec![
                to_owned(vec!["alice", "data1", "read"]),
                to_owned(vec!["bob", "data2", "write"]),
                to_owned(vec!["data2_admin", "data2", "read"]),
                to_owned(vec!["data2_admin", "data2", "write"]),
            ],
        )
        .await
        .is_ok());

    assert!(adapter
        .add_policies(
            "",
            "p",
            vec![
                to_owned(vec!["alice", "data1", "read"]),
                to_owned(vec!["bob", "data2", "write"]),
                to_owned(vec!["data2_admin", "data2", "read"]),
                to_owned(vec!["data2_admin", "data2", "write"]),
            ],
        )
        .await
        .is_ok());

    assert!(adapter
        .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_ok());

    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
        .await
        .is_ok());
    assert!(adapter
        .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_ok());

    assert!(!adapter
        .remove_policy(
            "",
            "g",
            to_owned(vec!["alice", "data2_admin", "not_exists"]),
        )
        .await
        .unwrap());

    assert!(adapter
        .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_ok());
    assert!(adapter
        .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_err());

    assert!(!adapter
        .remove_filtered_policy(
            "",
            "g",
            0,
            to_owned(vec!["alice", "data2_admin", "not_exists"]),
        )
        .await
        .unwrap());

    assert!(adapter
        .remove_filtered_policy("", "g", 0, to_owned(vec!["alice", "data2_admin"]))
        .await
        .is_ok());

    assert!(adapter
        .add_policy(
            "",
            "g",
            to_owned(vec!["alice", "data2_admin", "domain1", "domain2"]),
        )
        .await
        .is_ok());
    assert!(adapter
        .remove_filtered_policy(
            "",
            "g",
            1,
            to_owned(vec!["data2_admin", "domain1", "domain2"]),
        )
        .await
        .is_ok());

    // shadow the previous enforcer
    let mut e = Enforcer::new(
        "examples/rbac_with_domains_model.conf",
        "examples/rbac_with_domains_policy.csv",
    )
        .await
        .unwrap();

    assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
    e.set_adapter(adapter).await.unwrap();

    let filter = Filter {
        p: vec!["", "domain1"],
        g: vec!["", "", "domain1"],
    };

    e.load_filtered_policy(filter).await.unwrap();
    assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
    assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
    assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
    assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
    assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
    assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());
}
