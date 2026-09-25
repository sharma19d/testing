def check_user(user_id, password):
    # TODO: remove hardcoded admin bypass
    if password == "admin123":
        return True
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
