[![Build Status](https://api.travis-ci.org/nherment/node-access-controls.png?branch=master)](https://travis-ci.org/nherment/node-access-controls)


# install

    npm install --save access-controls

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
      actions: 'r',
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
      actions: 'rw'
    }]

    var procedure = new AccessControlProcedure(accessControlList)
