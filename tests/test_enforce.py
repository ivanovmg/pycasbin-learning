import pytest

from pycasbin_learning.enforce import (
    Account,
    Job,
    Permission,
    Role,
    User,
    enforce,
)


def test_owner_can_get_and_run_own_account_and_job():
    owner = 'alice'
    user = User(owner, roles=[])
    account = Account('foo', owner)
    job = Job('foo', owner)
    assert enforce(user, account, Permission.get)
    assert enforce(user, account, Permission.run)
    assert enforce(user, job, Permission.get)
    assert enforce(user, job, Permission.run)


@pytest.mark.parametrize(
    'resource',
    [Account('foo', 'bob'), Job('foo', 'bob')],
)
@pytest.mark.parametrize(
    'permission',
    [Permission.get, Permission.run],
)
def test_regular_user_cannot_perform_action_on_other_users_resources(
    resource,
    permission,
):
    user = User('alice', roles=[])
    assert not enforce(user, resource, permission)


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
