import casbin


def test_acl_model():
    # https://github.com/casbin/casbin/blob/master/examples/basic_model.conf
    # https://github.com/casbin/casbin/blob/master/examples/basic_policy.csv
    text = '''
            [request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
            '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)
    enforcer.add_policy('alice', 'data1', 'read')
    enforcer.add_policy('bob', 'data2', 'write')

    assert True is enforcer.enforce('alice', 'data1', 'read')
    assert True is enforcer.enforce('bob', 'data2', 'write')
    assert False is enforcer.enforce('alice', 'data1', 'write')
    assert False is enforcer.enforce('bob', 'data2', 'read')


def test_abac_model():
    # https://casbin.org/docs/en/abac
    class Resource:
        def __init__(self, owner):
            self.owner = owner

    text = '''
            [request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == r.obj.owner
            '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)

    assert True is enforcer.enforce('alice', Resource('alice'), 'foo')
    assert False is enforcer.enforce('alice', Resource('bob'), 'foo')


def test_restful_model():
    # https://github.com/casbin/casbin/blob/master/examples/keymatch_model.conf
    # https://github.com/casbin/casbin/blob/master/examples/keymatch_policy.csv
    text = '''
            [request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
            '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)
    enforcer.add_policy('alice', '/alice_data/*', 'GET')
    enforcer.add_policy('alice', '/alice_data/resource1', 'POST')
    enforcer.add_policy('bob', '/alice_data/resource2', 'GET')
    enforcer.add_policy('bob', '/bob_data/*', 'POST')
    enforcer.add_policy('cathy', '/cathy_data', '(GET)|(POST)')

    assert True is enforcer.enforce('alice', '/alice_data/hello', 'GET')
    assert True is enforcer.enforce('alice', '/alice_data/resource1', 'GET')
    assert True is enforcer.enforce('bob', '/bob_data/hello', 'POST')
    assert True is enforcer.enforce('cathy', '/cathy_data', 'GET')
    assert True is enforcer.enforce('cathy', '/cathy_data', 'POST')

    assert False is enforcer.enforce('alice', '/alice_data/hello', 'POST')
    assert False is enforcer.enforce('bob', '/alice_data/resource2', 'POST')
    assert False is enforcer.enforce('cathy', '/cathy_data', 'DELETE')


def test_customized_function():
    # https://casbin.org/docs/en/function#how-to-add-a-customized-function
    def key_match_func(key1, key2):
        return casbin.util.key_match(key1, key2)

    text = '''
            [request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && my_func(r.obj, p.obj) && r.act == p.act
            '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)
    enforcer.add_function(name='my_func', func=key_match_func)


def test_special_grammar():
    # https://casbin.org/docs/en/syntax-for-models#special-grammer
    text = '''
           [request_definition]
           r = sub, obj

           [policy_definition]
           p = sub, obj

           [policy_effect]
           e = some(where (p.eft == allow))

           [matchers]
           m = r.sub.name in (r.obj.admins)
           '''
    model = casbin.model.Model()
    model.load_model_from_text(text)
    enforcer = casbin.Enforcer(model)

    class Sub:
        name = 'alice'

    class Obj:
        name = 'a book'
        admins = ['alice', 'bob']

    assert True is enforcer.enforce(Sub(), Obj())
