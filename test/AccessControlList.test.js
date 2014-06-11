
var AccessControlList = require('../lib/AccessControlList.js')

var assert = require('assert')



describe('access control list', function() {

  it('single attribute single role', function(done) {

    var obj = {
      nested: {
        region: 'EMEA'
      }
    }

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load', 'save'],
      conditions: [{
          attributes: {
            'nested.region': 'EMEA'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)
    assert.ok(acl.shouldApply(obj, 'save').ok)
    assert.ok(!acl.shouldApply(obj, 'remove').ok)

    acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      acl.authorize(obj, 'remove', ['EMEA'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)

        acl.authorize(obj, 'load', ['APAC'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(!result.authorize)

          done()

        })

      })
    })


  })

  it('single action', function(done) {

    var obj = {region: 'EMEA'}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)
    assert.ok(!acl.shouldApply(obj, 'save').ok)
    assert.ok(!acl.shouldApply(obj, 'remove').ok)

    acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      done()

    })


  })

  it('should always apply on empty conditions', function(done) {

    var obj1 = {region: 'EMEA'}
    var obj2 = {region: 'APAC'}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['granted'],
      control: 'required',
      actions: ['load'],
      conditions: []
    })

    assert.ok(acl.shouldApply(obj1, 'load').ok)
    assert.ok(!acl.shouldApply(obj1, 'save').ok)
    assert.ok(!acl.shouldApply(obj1, 'remove').ok)

    assert.ok(acl.shouldApply(obj2, 'load').ok)
    assert.ok(!acl.shouldApply(obj2, 'save').ok)
    assert.ok(!acl.shouldApply(obj2, 'remove').ok)


    acl.authorize(obj1, 'load', ['granted'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      acl.authorize(obj2, 'load', ['denied'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })
    })


  })



  it('can apply to context', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [{
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)
    assert.ok(!acl.shouldApply(obj, 'save').ok)
    assert.ok(!acl.shouldApply(obj, 'remove').ok)

    acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      obj.owner = 1234
      acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })


  it('inheritance user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [
        '{user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)

    acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.ok(!result.inherit[0].entity.zone)
      assert.ok(!result.inherit[0].entity.base)
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })

  it('can handle inheritance sys/user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [
        '{sys/user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)

    acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.ok(!result.inherit[0].entity.zone)
      assert.equal(result.inherit[0].entity.base, 'sys')
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })

  it('can handle inheritance zone-1/sys/user::owner', function(done) {

    var obj = {region: 'EMEA', owner: 123}

    var acl = new AccessControlList({
      name: 'acl1_required',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [
        '{zone-1/sys/user::owner}',
        {
          attributes: {
            'owner': '{user.id}'
          }
        }
      ]
    })

    assert.ok(acl.shouldApply(obj, 'load').ok)

    acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)

      assert.ok(result.inherit)
      assert.equal(result.inherit[0].id, 123)
      assert.ok(result.inherit[0].entity)
      assert.equal(result.inherit[0].entity.zone, 'zone-1')
      assert.equal(result.inherit[0].entity.base, 'sys')
      assert.equal(result.inherit[0].entity.name, 'user')

      obj.owner = 1234
      acl.authorize(obj, 'load', ['EMEA'], {user: {id: 123}}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        done()

      })

    })


  })


})
