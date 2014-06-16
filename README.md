[![Build Status](https://api.travis-ci.org/nherment/node-access-controls.png?branch=master)](https://travis-ci.org/nherment/node-access-controls)


# install

### node.js

    npm install --save access-controls

### browser

Use the file in dist/access-controls.js

    <script src="access-controls.js"></script>


    var procedure = new AccessControls(accessControlList)

    procedure.authorize(obj, action, roles, context, function(err, authDecision) {
      // authDecision attributes
      // authorize: true | false
      // history: a list of the ACLs run
      // inherit: if there is an inheritance condition to access this entity
      // filters: an array of filters if some fields need filtering.
      //          You can use procedure.applyFilters(authDecision.filters, obj) to
      //          apply them
    })


# Usage

    var accessControlList = [{
      name: 'EMEA_region',
      roles: ['EMEA'],
      control: 'required',
      actions: 'r',
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
      actions: ['load', 'list', 'save', 'remove']
    }]

    var procedure = new AccessControlProcedure(accessControlList)

    proc = procedure.authorize(obj, context, action)

    proc.on('deny', function(details) {

    })

    proc.on('grant', function(details) {

    })

    proc.on('dependency', function(details) {

    })


## Access Controls

An access control procedure runs a set of ACLs against a given pair of ```entity``` and ```action```

An ACL is composed of:

- a list of roles which are required for this ACL to authorize
- a set of actions (save, update, get, list)
- on a given entity (the type as well as specific attributes values)
- a control type (one of required|requisite|sufficient) that determine what happens should the ACL fail or succeed:
  - ```required``` — The service result must be successful for authentication to continue. If the test fails at this point, the user is not notified until the results of all service tests that reference that interface are complete.
  - ```requisite``` — The service result must be successful for authentication to continue. However, if a test fails at this point, the user is notified immediately with a message reflecting the first failed required or requisite service test.
  - ```sufficient``` — The service result is ignored if it fails. However, if the result of a service flagged sufficient is successful and no previous services flagged required have failed, then no other results are required and the user is authenticated to the service.

> IMPORTANT: The order in which ```required``` ACLs are called is not critical. Only the ```sufficient``` and ```requisite``` control flags cause order to become important.

Examples:
```
    si.use( '..', {
      accessControls: [{
        name: 'access to foobar entities',
        roles: ['foobar'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['save', 'load', 'list', 'remove'],
        conditions: []
      },{
        name: 'access to foobar EMEA entities',
        roles: ['EMEA'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'required',
        actions: ['save', 'load', 'list', 'remove'],
        conditions: [{
            attributes: {
              'region': 'EMEA'
            }
          }
        ]
      },{
        name: 'access to foobar EMEA entities',
        roles: ['private_items'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'item'
        }],
        control: 'required',
        actions: ['load'],
        conditions: [{
            attributes: {
              'status': 'private'
            }
          }
        ]
      }]
    })
```

### Field level access/masking

Field masking works a bit differently compared to other ACLs.

It is possible to mask or deny access to specific fields IF the access roles are not met.

For example:

    si.use( '..', {
      accessControls: [{
        name: 'access to foobar entities',
        roles: ['foobar', 'ssn'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'foobar'
        }],
        control: 'filter',
        actions: ['load'],
        conditions: [{
            attributes: {
              'status': 'private'
            }
          }
        ],
        filters: {
          lastName: false,
          ssn: function(value) {
            if(value) {
              value = '***-***-' + value.substr(-4)
            }
          }
        }
      }]
    })

Will:

- mask the field ```ssn``` and only display the last 4 digits
- completely hide the field ```lastName```

for all access except those with roles ```foobar``` and ```ssn```.

### manual validation

You can manually invoke the ACLs by setting the ```perm$``` attribute in the arguments:

      var publicAccess = si.delegate({perm$:{roles:[]}})
      var pf1 = publicAccess.make('item',{number: 1, status: 'public'})

      var privateAccess = si.delegate({perm$:{roles:['private_items']}})
      var pf2 = privateAccess.make('item',{number: 2, status: 'private'})

### current context

In some cases, you want to run access controls against the current logged in user.
For this, you can reference the current user in an ACL:


    si.use( '..', {
      accessControls: [{
        name: 'todos: owner only',
        roles: ['my_todos'],
        entities: [{
          zone: undefined,
          base: undefined,
          name: 'todo'
        }],
        control: 'required',
        actions: ['save', 'load', 'list', 'remove'],
        conditions: [{
            attributes: {
              'owner': '{user.id}'
            }
          }
        ]
      }]
    })

The above will allow users to only create, read, update or delete 'todo' objects where they are the owner.
