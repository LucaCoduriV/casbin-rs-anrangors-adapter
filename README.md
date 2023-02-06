[![crates.io](https://img.shields.io/crates/v/casbin-arangors-adapter.svg)](https://crates.io/crates/casbin-arangors-adapter)
# Casbin-rs Arangors adapter

## How to use
To make this crate work you need to create a collection named `casbin`.
Don't forget to put The unique key index on columns `ptype,v0,v1,v2,v3,v4,v5`

In code example:
```rust
use casbin_arangors_adapter::ArangorsAdapter;

let conn = arangors::Connection::establish_jwt(
    constants::DB_ADDRESS.as_str(),
    constants::DB_USER.as_str(),
    constants::DB_PASSWORD.as_str(),
).await.unwrap();

let db = conn.db(constants::DB_NAME.as_str()).await.unwrap();


let adapter = ArangorsAdapter::new(db);
let mut e = Enforcer::new("./model.conf", adapter).await.unwrap();
e.add_policy(vec!["jack".to_owned(), "data4".to_owned(), "read".to_owned()]).await;

assert!(e.enforce(("jack", "data4", "read")).unwrap());
assert!(!e.enforce(("jack", "data4", "write")).unwrap());
```

## Disclaimer

The crate is not 100% tested and will maybe have some bugs.
Feel free to make a pull request to fix those bugs 😃.

The code can be improved for sure but it wasn't the main goal.


A lot of the code was taken from this repo: https://github.com/casbin-rs/diesel-adapter
