import casbin


class Permission:
    get = 'get'
    run = 'run'


class Account:
    def __init__(self, id, owner):
        self.id = f'account/{id}'
        self.owner = owner


class Job:
    def __init__(self, id, owner):
        self.id = f'job/{id}'
        self.owner = owner


class User:
    def __init__(self, id, roles):
        self.id = id
        self.roles = roles


class Role:
    admin = 'admin'
    management = 'management '


def enforce(user, resource, permission):
    text = '''
            [request_definition]
            r = user, resource, permission

            [policy_definition]
            p = user, resource, permission

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.user.id == r.resource.owner
            '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)
    return enforcer.enforce(user, resource, permission)
