use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum OutputError {
    SameAsInput { input: PathBuf, output: PathBuf },
    InvalidPath(PathBuf),
    Canonicalize { path: PathBuf, source: io::Error },
    Open { path: PathBuf, source: io::Error },
    Metadata { path: PathBuf, source: io::Error },
    Write { path: PathBuf, source: io::Error },
}

impl Display for OutputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SameAsInput { input, output } => write!(
                formatter,
                "refusing to overwrite input evidence {} with report output {}",
                input.display(),
                output.display()
            ),
            Self::InvalidPath(path) => {
                write!(
                    formatter,
                    "output path has no file name: {}",
                    path.display()
                )
            }
            Self::Canonicalize { path, source } => {
                write!(
                    formatter,
                    "cannot canonicalize {}: {source}",
                    path.display()
                )
            }
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "cannot open report output {}: {source}",
                    path.display()
                )
            }
            Self::Metadata { path, source } => write!(
                formatter,
                "cannot read file identity for {}: {source}",
                path.display()
            ),
            Self::Write { path, source } => {
                write!(
                    formatter,
                    "cannot write report output {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for OutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SameAsInput { .. } | Self::InvalidPath(_) => None,
            Self::Canonicalize { source, .. }
            | Self::Open { source, .. }
            | Self::Metadata { source, .. }
            | Self::Write { source, .. } => Some(source),
        }
    }
}

pub fn write_report(path: &Path, input_path: &Path, contents: &str) -> Result<(), OutputError> {
    reject_path_alias(path, input_path)?;

    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| OutputError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let input = File::open(input_path).map_err(|source| OutputError::Open {
        path: input_path.to_path_buf(),
        source,
    })?;
    if same_file_identity(&input, &output, input_path, path)? {
        return Err(OutputError::SameAsInput {
            input: input_path.to_path_buf(),
            output: path.to_path_buf(),
        });
    }

    output.set_len(0).map_err(|source| OutputError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    output
        .write_all(contents.as_bytes())
        .map_err(|source| OutputError::Write {
            path: path.to_path_buf(),
            source,
        })
}

fn reject_path_alias(output: &Path, input: &Path) -> Result<(), OutputError> {
    let canonical_input = input
        .canonicalize()
        .map_err(|source| OutputError::Canonicalize {
            path: input.to_path_buf(),
            source,
        })?;
    let canonical_output = if output.exists() {
        output
            .canonicalize()
            .map_err(|source| OutputError::Canonicalize {
                path: output.to_path_buf(),
                source,
            })?
    } else {
        let file_name = output
            .file_name()
            .ok_or_else(|| OutputError::InvalidPath(output.to_path_buf()))?;
        let parent = output.parent().filter(|path| !path.as_os_str().is_empty());
        let parent = parent.unwrap_or_else(|| Path::new("."));
        let canonical_parent =
            parent
                .canonicalize()
                .map_err(|source| OutputError::Canonicalize {
                    path: parent.to_path_buf(),
                    source,
                })?;
        canonical_parent.join(file_name)
    };

    if canonical_input == canonical_output {
        return Err(OutputError::SameAsInput {
            input: input.to_path_buf(),
            output: output.to_path_buf(),
        });
    }
    Ok(())
}

fn same_file_identity(
    input: &File,
    output: &File,
    input_path: &Path,
    output_path: &Path,
) -> Result<bool, OutputError> {
    let input_metadata = input.metadata().map_err(|source| OutputError::Metadata {
        path: input_path.to_path_buf(),
        source,
    })?;
    let output_metadata = output.metadata().map_err(|source| OutputError::Metadata {
        path: output_path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(input_metadata.dev() == output_metadata.dev()
            && input_metadata.ino() == output_metadata.ino())
    }

    #[cfg(not(unix))]
    {
        let _ = (input_metadata, output_metadata);
        input_path
            .canonicalize()
            .and_then(|input| output_path.canonicalize().map(|output| input == output))
            .map_err(|source| OutputError::Canonicalize {
                path: output_path.to_path_buf(),
                source,
            })
    }
}
