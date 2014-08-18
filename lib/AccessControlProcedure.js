var _        = require('lodash')
var ACL      = require('../lib/AccessControlList.js')
var patrun   = require('patrun')

/** An access control procedure runs a set of ACLs against a given pair of <entity> and <action>
 */
function AccessControlProcedure(acls) {

  this._accessControls = []
  if(acls) {
    this.addAccessControls(acls)
  }

}

AccessControlProcedure.ACL = ACL

AccessControlProcedure.generateActionsMapping = function(accessControls) {

  var mapping = patrun()
  for(var i = 0 ; i < accessControls.length ; i++) {
    var aclDefinition = accessControls[i]

    for(var j = 0 ; j < aclDefinition.entities.length ; j++) {

      var actions = aclDefinition.actions
      for(var k = 0 ; k < actions.length ; k++) {

        var argsMatching = _.clone(aclDefinition.entities[j])

        argsMatching.role = 'entity'

        // TODO: differentiate create from update
        switch(actions[k]) {
          case 'save':
          case 'save_new':
          case 'save_existing':
            argsMatching.cmd = 'save'
            break
          case 'load':
            argsMatching.cmd = 'load'
            break
          case 'list':
            argsMatching.cmd = 'list'
            break
          case 'remove':
            argsMatching.cmd = 'remove'
            break
          default:
            throw new Error('unsupported action ['+actions[k]+'] in ' + JSON.stringify(aclDefinition))
        }

        var aclProcedure = mapping.find(argsMatching)

        if(!aclProcedure) {
          aclProcedure = new AccessControlProcedure()
          mapping.add(argsMatching, aclProcedure)
        }

        aclProcedure.addAccessControls(aclDefinition)
      }
    }
  }
  return mapping
}

/**
 * mapping: patrun mapping returned by AccessControlProcedure.generateActionsMapping()
 * entityDef: { zone: ..., base: ..., name: ... }
 * action: 'load' | 'list' | 'save' | 'remove'
 */
AccessControlProcedure.getProcedureForEntity = function(mapping, entityDef, action) {
  return mapping.find({role: 'entity', zone: entityDef.zone, base: entityDef.base, name: entityDef.name, cmd: action})
}

AccessControlProcedure.prototype.addAccessControls = function(acl) {
  if(_.isArray(acl)) {
    for(var i = 0 ; i < acl.length ; i++) {
      this.addAccessControls(acl[i])
    }
  } else if(_.isObject(acl)) {
    this._accessControls.push(new ACL(acl))
  } else {
    throw new Error('unsuported ACL object type: ' + typeof acl)
  }
}

AccessControlProcedure.prototype.authorize = function(obj, action, roles, context, callback) {
  //console.log('Running authorization procedure', obj, action, roles)

  this._nextACL(obj, action, roles, this._accessControls.slice(0), context, undefined, function(err, details) {
    callback(err, details)
  })
}

AccessControlProcedure.prototype._nextACL = function(obj, action, roles, accessControls, context, details, callback) {
  if(!details) {
    details = {authorize: true}
  }
  if(!details.history) {
    details.history = []
  }
  if(!details.inherit) {
    details.inherit = []
  }
  details.context = context
  details.roles   = roles
  details.action  = action
  var self = this

  if(accessControls && accessControls.length > 0) {
    var accessControl = accessControls.shift()
    var shouldApply = accessControl.shouldApply(obj, action)
    if(shouldApply.ok) {
      //console.log('running authorization service', accessControl.name())
      accessControl.authorize(obj, action, roles, context, function(err, result) {

        details.history.push({
          service: accessControl.name(),
          authorize: result ? result.authorize : null,
          control: accessControl.control(),
          err: err || null,
          reason: result ? result.reason : null
        })

        //console.log(obj, action, roles, JSON.stringify(result))

        if(err || !result) {
          details.authorize = false
          callback(err, details)
        }

        if(result.inherit) {
          details.inherit = details.inherit.concat(result.inherit)
        }

        var stop = false

        switch(accessControl.control()) {
          case 'filter':
            if(result.hard) {
              details.hard = true;
            } else {
              details.hard = false;
            }
            if(!details.filters) {
              details.filters = []
            }
            if(result.filters) {
              details.filters = details.filters.concat(result.filters)
            }
            break
          case 'requisite':
            if(result.hard) {
              details.hard = true;
            } else {
              details.hard = false;
            }
            if(!result.authorize) {
              details.authorize = false
              stop = true
            }
            break
          case 'required':
            if(result.hard) {
              details.hard = true;
            } else {
              details.hard = false;
            }
            if(!result.authorize) {
              details.authorize = result.authorize
            }
            break
          case 'sufficient':
            if(result.authorize) {
              details.authorize = true
              stop = true
            }
            break
        }

        if(stop) {
          callback(undefined, details)
        } else {
          self._nextACL(obj, action, roles, accessControls, context, details, callback)
        }
      })
    } else {
      //console.log('ignoring authorization service', accessControl.name(), '. reason:', shouldApply.reason)
      self._nextACL(obj, action, roles, accessControls, context, details, callback)
    }
  } else {
    callback(undefined, details)
  }
}

AccessControlProcedure.prototype.applyFilters = function(filters, obj, action) {

  var filterType = 'read'
  switch(action) {
    case 'save':
    case 'save_new':
    case 'save_existing':
      filterType = 'write'
      break
    case 'load':
    case 'list':
    default:
      filterType = 'read'
      break
  }

  if(filters && filters.length > 0) {
    for(var i = 0 ; i < filters.length ; i++) {
      var filter = filters[i]

      switch(filter.access) {
      case 'denied':
          delete obj[filter.attribute]

          break
        case 'partial':
          if(filterType === 'read') {
            obj[filter.attribute] = filter.filteredValue
          } else {
            delete obj[filter.attribute]
          }
          break
      }

    }
  }

}

module.exports = AccessControlProcedure
