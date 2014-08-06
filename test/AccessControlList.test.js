
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

  it('should fail to allow blacklisted numbers', function(done){
    // Story: Each state (entity) has a number of zip codes that are
    // not allowed to participate in a competition. These zip codes
    // are listed as an array under the zipBlacklist property.
    // We need to make sure that the context object (a city with a zip)
    // is not in this list and fail authorization if it is.
    var numberObj = {
      state: 'Arizona',
      zipBlacklist: ['85050', '85260']
    };

    var acl = new AccessControlList({
      name: 'Check for Blacklist',
      roles: ['agent'],
      control: 'required',
      actions: ['save','list','load'],
      conditions: [{
        attributes: {
          'zipBlacklist': '{!city.zip}'
        }
      }]
    });

    assert.ok(acl.shouldApply(numberObj, 'load').ok);

    acl.authorize(numberObj, 'load', ['agent'], {city: {zip: '85050'}}, function(err, result) {

      assert.ok(!err, err);

      assert.ok(result);
      // Fail authorization because zip is in the blacklist
      assert.ok(!result.authorize);
    });

    done();

  });

  it('should authorize when blacklisted numbers are not present', function(done){
    var numberObj = {
      state: 'Arizona',
      zipBlacklist: ['85050', '85260']
    };

    var acl = new AccessControlList({
      name: 'Check for Blacklist',
      roles: ['agent'],
      control: 'required',
      actions: ['save','list','load'],
      conditions: [{
        attributes: {
          'zipBlacklist': '{!city.zip}'
        }
      }]
    });

    assert.ok(acl.shouldApply(numberObj, 'load').ok);

    acl.authorize(numberObj, 'load', ['agent'], {city: {zip: '85555'}}, function(err, result) {

      assert.ok(!err, err);

      assert.ok(result);
      // Should authorization because zip is not in the blacklist
      assert.ok(result.authorize);
    });

    done();

  });

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

  describe('attributes filtering', function() {

    it('denied', function(done) {

      var obj = {date: Date.now(), region: 'EMEA'}

      var acl = new AccessControlList({
        name: 'acl1_filter',
        roles: ['EMEA'],
        control: 'filter',
        actions: ['load'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ],
        filters: {
          region: false
        }
      })

      acl.authorize(obj, 'load', ['APAC'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)
        assert.ok(result.filters)
        assert.equal(result.filters.length, 1)
        assert.equal(result.filters[0].attribute, 'region')
        assert.equal(result.filters[0].access, 'denied')


        acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(result.authorize)
          assert.ok(!result.filters)

          done()

        })

      })


    })

    it('mask', function(done) {

      var obj = {date: Date.now(), region: 'EMEA', sin: '123-456-789', ssn1: '123-456-7890', ssn2: '123-456-7890', ssn3: '123-456-7890'}

      var acl = new AccessControlList({
        name: 'acl2_filter',
        roles: ['EMEA'],
        control: 'filter',
        actions: ['load'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ],
        filters: {
          sin: function(value) {
            if(value && value.length > 0) {
              return '***-***-' + value.substr(-3)
            } else {
              return '***-***-***'
            }
          },
          ssn1: -4, // mask all except the last 4 characters
          ssn2: 3,  // mask all except the first 3 characters
          ssn3: -50,
          ssn4: 12
        }
      })


      acl.authorize(obj, 'load', ['APAC'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)
        assert.ok(result.filters)
        assert.equal(result.filters.length, 5)
        assert.equal(result.filters[0].attribute, 'sin')
        assert.equal(result.filters[0].access, 'partial')
        assert.equal(result.filters[0].originalValue, '123-456-789')
        assert.equal(result.filters[0].filteredValue, '***-***-789')

        assert.equal(result.filters[1].attribute, 'ssn1')
        assert.equal(result.filters[1].access, 'partial')
        assert.equal(result.filters[1].originalValue, '123-456-7890')
        assert.equal(result.filters[1].filteredValue, '********7890')

        assert.equal(result.filters[2].attribute, 'ssn2')
        assert.equal(result.filters[2].access, 'partial')
        assert.equal(result.filters[2].originalValue, '123-456-7890')
        assert.equal(result.filters[2].filteredValue, '123*********')

        assert.equal(result.filters[3].attribute, 'ssn3')
        assert.equal(result.filters[3].access, 'partial')
        assert.equal(result.filters[3].originalValue, '123-456-7890')
        assert.equal(result.filters[3].filteredValue, '123-456-7890')

        assert.equal(result.filters[4].attribute, 'ssn4')
        assert.equal(result.filters[4].access, 'denied')
        assert.equal(result.filters[4].originalValue, undefined)

        acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(result.authorize)
          assert.ok(!result.filters)

          done()

        })

      })

    })


    it('mask, denied and non existing attr', function(done) {

      var obj = {date: Date.now(), region: 'EMEA', sin: '123-456-789'}

      var acl = new AccessControlList({
        name: 'acl2_filter',
        roles: ['EMEA'],
        control: 'filter',
        actions: ['load'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ],
        filters: {
          foo: false,
          region: false,
          sin: function(value) {
            if(value && value.length > 0) {
              return '***-***-' + value.substr(-3)
            } else {
              return '***-***-***'
            }
          }
        }
      })


      acl.authorize(obj, 'load', ['APAC'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)
        assert.ok(result.filters)
        assert.equal(result.filters.length, 3)

        assert.equal(result.filters[0].attribute, 'foo')
        assert.equal(result.filters[0].access, 'denied')
        assert.equal(result.filters[0].originalValue, undefined)

        assert.equal(result.filters[1].attribute, 'region')
        assert.equal(result.filters[1].access, 'denied')
        assert.equal(result.filters[1].originalValue, 'EMEA')

        assert.equal(result.filters[2].attribute, 'sin')
        assert.equal(result.filters[2].access, 'partial')
        assert.equal(result.filters[2].filteredValue, '***-***-789')
        assert.equal(result.filters[2].originalValue, '123-456-789')

        acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(result.authorize)
          assert.ok(!result.filters)

          done()

        })

      })

    })


    it('does not filter when the conditions are not met', function(done) {

      var obj = {date: Date.now(), region: 'APAC', sin: '123-456-789'}

      var acl = new AccessControlList({
        name: 'acl2_filter',
        roles: ['EMEA'],
        control: 'filter',
        actions: ['load'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ],
        filters: {
          sin: function(value) {
            if(value && value.length > 0) {
              return '***-***-' + value.substr(-3)
            } else {
              return '***-***-***'
            }
          }
        }
      })


      acl.authorize(obj, 'load', ['APAC'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)
        assert.ok(!result.filters)

        acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(result.authorize)
          assert.ok(!result.filters)

          done()

        })

      })

    })

  })


  it('write denied', function(done) {

    var obj = {date: Date.now(), region: 'EMEA'}

    var acl = new AccessControlList({
      name: 'acl1_filter',
      roles: ['EMEA'],
      control: 'filter',
      actions: ['save_new'],
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ],
      filters: {
        region: false
      }
    })

    acl.authorize(obj, 'save_new', ['APAC'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)
      assert.ok(result.filters)
      assert.equal(result.filters.length, 1)
      assert.equal(result.filters[0].attribute, 'region')
      assert.equal(result.filters[0].access, 'denied')


      acl.authorize(obj, 'load', ['EMEA'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(result.authorize)
        assert.ok(!result.filters)

        done()

      })

    })


  })


  it('remove denied', function(done) {

    var obj = {date: Date.now(), region: 'EMEA'}

    var acl = new AccessControlList({
      name: 'acl1_filter',
      roles: ['EMEA'],
      control: 'required',
      actions: ['remove'],
      conditions: [{
          attributes: {
            'region': 'EMEA'
          }
        }
      ]
    })

    acl.authorize(obj, 'save_new', ['EMEA'], {}, function(err, result) {

      assert.ok(!err, err)

      assert.ok(result)
      assert.ok(result.authorize)


      acl.authorize(obj, 'remove', ['APAC'], {}, function(err, result) {

        assert.ok(!err, err)

        assert.ok(result)
        assert.ok(!result.authorize)

        acl.authorize(obj, 'remove', ['EMEA'], {}, function(err, result) {

          assert.ok(!err, err)

          assert.ok(result)
          assert.ok(result.authorize)

          done()

        })

      })

    })


  })



})
