# Contributing to Reticulum-rs

We welcome and value all kinds of contributions to **Reticulum-rs**. These are our guidelines to make collaboration easier.

## I have a question

If your question is related to the Reticulum network stack itself, you will likely find an answer in the [Reticulum manual](https://reticulum.network/docs.html). If it is specific to Reticulum-rs, someone may have already opened a github issue about it. If not, feel free to open a new issue.

## I want to report a bug

Please make sure that you are running the latest version, and that the bug is indeed a bug and not an error on your side.

Please consider also that Reticulum-rs is not a complete implementation of the Reticulum network stack yet, and that unexpected behavior might be caused by a part of the protocol still missing.

If all that is ruled out and your problem still looks like a bug, and if nobody else opened an issue about it yet, please open an issue to let us know about it. As far as possible, include

- expected behavior

- actual behavior

- logs and error messages

- steps to reproduce

- possible cause/suggested fix

in your report.

## Code contributions

If you want to contribute to the programming of **Reticulum-rs**, the easiest way is to find an issue to work on and let us know you want to work on it. Maybe you also have your own idea how to enhance the project, in which case we encourage you to open your own issue.

In any case, **please use the issue tracker to talk to us first.** Your idea may not fit our plan for further development, or it may be based on misunderstandings of the project architecture that can easily happen. We would hate to have to reject a big PR that took you several hours to complete.

### Programming style

Please follow the usual [Rust programming style](https://doc.rust-lang.org/style-guide/).

### Use of AI tools

It is common nowadays to use AI tools for syntax completion, to generate boilerplate, to find common and trivial bugs etc, and these uses of AI are encouraged for Reticulum-rs contributions too.

However, we do not see full-scale code generation ("vibe coding") in its current stage of development as appropriate for collaboratively written software such as ours. Contributions still need to be reviewed manually, and large generated PRs can become disruptive for a small team like ours. Therefore, **please do not submit vibe coded PRs**, not even if they pass all the vibe coded tests.

### Commit messages

We use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) standard for commit messages.
