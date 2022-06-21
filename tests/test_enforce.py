from src.enforce import enforce, User, Account, Job, Permission, Role


def test_owner_can_get_and_run_own_account_and_job():
    owner = 'alice'
    user = User(owner, roles=[])
    account = Account('foo', owner)
    job = Job('foo', owner)
    assert enforce(user, account, Permission.get)
    assert enforce(user, account, Permission.run)
    assert enforce(user, job, Permission.get)
    assert enforce(user, job, Permission.run)


def test_admin_can_get_and_run_all_account_and_job():
    user = User('alice', roles=[Role.admin])
    account = Account('foo', 'bob')
    job = Job('foo', 'bob')
    assert enforce(user, account, Permission.get)
    assert enforce(user, account, Permission.run)
    assert enforce(user, job, Permission.get)
    assert enforce(user, job, Permission.run)


def test_management_can_get_all_account():
    user = User('alice', roles=[Role.management])
    account = Account('foo', 'bob')
    assert enforce(user, account, Permission.get)


def test_management_can_run_all_job():
    user = User('alice', roles=[Role.management])
    job = Job('foo', 'bob')
    assert enforce(user, job, Permission.run)
