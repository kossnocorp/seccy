//! Shared structured output, with jq-compatible filtering before serialization.
use anyhow::{Result, anyhow};
use jaq_core::{
    Ctx, Vars, data,
    load::{Arena, File, Loader},
    unwrap_valr,
};
use jaq_json::Val;
use serde_json::Value;
use std::{io::Write, sync::Arc};

type Filter = jaq_core::Filter<data::JustLut<Val>>;

#[derive(Clone, Default)]
pub struct Output {
    json: bool,
    query: Option<Arc<Filter>>,
}

/// Kept distinct from command errors: never run a failed filter on its own error.
#[derive(Debug)]
pub struct QueryError(String);

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "query: {}", self.0)
    }
}

impl std::error::Error for QueryError {}

impl Output {
    pub fn new(json: bool, query: Option<&str>) -> Result<Self> {
        let query = query
            .map(|code| {
                let defs = jaq_core::defs()
                    .chain(jaq_std::defs())
                    .chain(jaq_json::defs());
                let funs = jaq_core::funs()
                    .chain(jaq_std::funs())
                    .chain(jaq_json::funs());
                let arena = Arena::default();
                let modules = Loader::new(defs)
                    .load(&arena, File { code, path: () })
                    .map_err(|e| QueryError(format!("parse error: {e:?}")))?;
                let filter = jaq_core::Compiler::default()
                    .with_funs(funs)
                    .compile(modules)
                    .map_err(|e| QueryError(format!("compile error: {e:?}")))?;
                Ok::<_, anyhow::Error>(Arc::new(filter))
            })
            .transpose()?;
        Ok(Self { json, query })
    }

    pub fn structured(&self) -> bool {
        self.json || self.query.is_some()
    }

    pub fn emit(&self, value: Value, text: &str) -> Result<()> {
        self.write(&mut std::io::stdout().lock(), value, text)
    }

    fn write(&self, out: &mut impl Write, value: Value, text: &str) -> Result<()> {
        if let Some(filter) = &self.query {
            let bytes = serde_json::to_vec(&value)?;
            let input = jaq_json::read::parse_single(bytes.as_slice())
                .map_err(|e| anyhow!("query input: {e:?}"))?;
            let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
            let pp = jaq_json::write::Pp {
                indent: Some("  ".into()),
                sep_space: true,
                ..Default::default()
            };
            for result in filter.id.run((ctx, input)).map(unwrap_valr) {
                let value = result.map_err(|e| QueryError(e.to_string()))?;
                jaq_json::write::write(out, &pp, 0, &value)?;
                writeln!(out)?;
            }
        } else if self.json {
            writeln!(out, "{value}")?;
        } else if !text.is_empty() {
            writeln!(out, "{text}")?;
        }
        out.flush()?;
        Ok(())
    }
}
