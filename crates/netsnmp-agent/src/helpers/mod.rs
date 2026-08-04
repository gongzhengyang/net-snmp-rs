//! Table and helper toolbox.
//!
//! Counterpart of the C `agent/helpers/` directory. Each submodule ports one
//! helper as an implementation of [`crate::handler::MibHandler`], composable
//! through `Arc<dyn MibHandler>`.
//!
//! | Module                | C counterpart                       |
//! |-----------------------|-------------------------------------|
//! | [`table`]             | `table.c` + `table_data.c`          |
//! | [`table_dataset`]     | `table_dataset.c`                   |
//! | [`cache_handler`]     | `cache_handler.c`                   |
//! | [`watcher`]           | `watcher.c`                         |
//! | [`read_only`]         | `read_only.c`                       |

pub mod cache_handler;
pub mod read_only;
pub mod table;
pub mod table_dataset;
pub mod watcher;

pub use cache_handler::CacheHandler;
pub use read_only::{read_only, ReadOnly};
pub use table::{Row, TableHandler};
pub use table_dataset::{ColumnMeta, TableDataSet};
pub use watcher::Watcher;
