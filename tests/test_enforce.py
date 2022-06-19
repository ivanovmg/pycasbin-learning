from src.enforce import enforce, User, Account, Job, Permission


def test_owner_can_get_and_run_own_account_and_job():
    owner = 'alice'
    user = User(owner, roles=[])
    account = Account('foo', owner)
    job = Job('foo', owner)
    assert enforce(user, account, Permission.get)
    assert enforce(user, account, Permission.run)
    assert enforce(user, job, Permission.get)
    assert enforce(user, job, Permission.run)
