# Contributing

Bug reports, ideas and pull requests are welcome. This is a young project, so please open an issue before a large change.

## Run the tests
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cd app && TEST_SQLITE=1 python manage.py test
```
Tests use SQLite and the `dryrun` backend. They never touch a real mail server.

## Rules
- Keep secrets out of commits. `.env` is ignored; use `.env.example` for new settings.
- Add a test for every behavior change.
- Public text is bilingual (English and Turkish). The Turkish text prevails in legal pages.
- By contributing you agree your code is licensed under AGPL-3.0, like the rest of the project.

## Reporting a security problem
See [SECURITY.md](SECURITY.md). Do not open a public issue.
