
var AccessControlProcedure = require('../lib/AccessControlProcedure.js')

var assert = require('assert')



describe('access controls', function() {
  describe('procedure 1', function() {

    var accessControlList1 = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    }, {
      name: 'legal_group',
      roles: ['legal'],
      control: 'required',
      actions: ['load'],
      conditions: [{
          attributes: {
            'group': 'legal'
          }
        }
      ]
    }, {
      name: 'admin all access',
      roles: ['admin'],
      control: 'sufficient',
      actions: ['load', 'save']
    }]

    var procedure1 = new AccessControlProcedure(accessControlList1)

    var emeaLegal = {
      region: 'EMEA',
      group: 'legal'
    }
    var emeaHR = {
      region: 'EMEA',
      group: 'HR'
    }
    var apacHR = {
      region: 'APAC',
      group: 'HR'
    }

    it('match', function(done) {

      procedure1.authorize(emeaLegal, 'load', ['EMEA', 'legal'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        done()
      })

    })

    it('rejected by the second required', function(done) {

      procedure1.authorize(emeaLegal, 'load', ['EMEA'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, true)
        assert.equal(result.history[1].authorize, false)
        done()
      })

    })

    it('rejected by the first required', function(done) {

      procedure1.authorize(emeaLegal, 'load', ['legal'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, true)
        done()
      })

    })

    it('no conditions "sufficient" in ACL gives all access', function(done) {

      procedure1.authorize(emeaLegal, 'load', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList1.length)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, false)
        assert.equal(result.history[2].authorize, true)
        done()
      })

    })
  })


  describe('procedure 2', function() {

    var accessControlList2 = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      actions: ['load'],
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    }, {
      name: 'admin all access',
      roles: ['admin'],
      control: 'sufficient',
      actions: ['load', 'save']
    }, {
      name: 'does_not_exist all access',
      roles: ['requisite'],
      control: 'requisite',
      actions: ['load', 'save']
    }, {
      name: 'never_used_all_access',
      roles: ['all_access'],
      control: 'sufficient',
      actions: ['load', 'save']
    }]

    var procedure2 = new AccessControlProcedure(accessControlList2)

    var emea = {
      region: 'EMEA'
    }

    it('match', function(done) {

      procedure2.authorize(emea, 'load', ['EMEA', 'requisite'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, accessControlList2.length)
        done()
      })

    })


    it('no conditions "sufficient" in ACL gives all access', function(done) {

      procedure2.authorize(emea, 'load', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, 2)
        assert.equal(result.history[0].authorize, false)
        assert.equal(result.history[1].authorize, true)
        done()
      })

    })

    it('"requisite" is absolutely mandatory', function(done) {

      procedure2.authorize(emea, 'load', ['EMEA', 'all_access'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.equal(result.history.length, 3)
        assert.equal(result.history[0].authorize, true)
        assert.equal(result.history[1].authorize, false)
        assert.equal(result.history[2].authorize, false)
        done()
      })

    })
  })

  describe('procedure 3', function () {

    var accessControlList3 = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      hard: true,
      actions: ['load']
    },
    {
      name: 'EMEA_region2',
      roles: ['EMEA2'],
      control: 'required',
      hard: false,
      actions: ['list']
    }
  ]

    var region1 = {
      name: 'EMEA' 
    }

    var region2 = {
      name: 'EMEA2'
    }
  
    var procedure3 = new AccessControlProcedure(accessControlList3)

    it('match', function(done) {

      procedure3.authorize(region1, 'load', ['EMEA'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(result.authorize)
        assert.equal(result.history.length, 1)
        done()
      })

    })

    it('access denied - hard set to true', function(done) {
      procedure3.authorize(region1, 'load', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }

        assert.ok(result)
        assert.ok(!result.authorize)
        assert.ok(result.hard)
        done()
      })
    })

    it('access denied - hard set to false', function(done) {
      procedure3.authorize(region2, 'list', ['admin'], {}, function(err, result) {
        if(err) {
          return done(err)
        }
        assert.ok(result)
        assert.ok(!result.authorize)
        assert.ok(!result.hard)
        done()
      })
    })

  })

})
