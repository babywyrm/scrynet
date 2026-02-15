# Rules Changelog

Rule additions and changes. See `docs/STATIC_SCANNER_STRATEGY.md` for roadmap. Validate with `python3 scripts/validate_rules.py`.

## 2026-02

### Added
- **Prisma Unsafe Raw SQL** (CRITICAL): `$queryRawUnsafe`, `$executeRawUnsafe`, raw SQL with concatenation
- **React dangerouslySetInnerHTML** (HIGH): XSS when rendering user-controlled HTML
- **Go SQL with fmt.Sprintf** (CRITICAL): SQL built with `fmt.Sprintf` instead of parameterized queries
- **Ruby ActiveRecord Raw SQL** (CRITICAL): `execute`/`select_all`/`find_by_sql` with `#{...}` or string concat
- **Java/Spring**: `@Query` concatenation, `permitAll` on sensitive paths, RestTemplate/WebClient SSRF, JPA `createNativeQuery`, `@RequestBody` to repository, Quarkus `deny-unauthenticated=false`
- **Python**: Django `raw()`/`extra()` with f-string, SQLAlchemy `text()` with f-string, FastAPI `Body` to ORM, request in query, `format` in SQL, Celery pickle, Pydantic `model_dump` to ORM
- **Node.js/Mongoose**: `findByIdAndUpdate(req.body)`, `Model.update(req.body)`, mass assignment, `req.params` in MongoDB query

### Scanner
- Extended file types: `.ts`, `.tsx`, `.rb`, `.yml`, `.yaml`
