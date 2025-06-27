Any function which can read the database will be prefixed with read_ when imported in app.py.
Any function which can modify the database will be prefixed with write_ when imported in app.py.
The four exceptions to this rule are init_db, seed_db, admin_required and login_required.