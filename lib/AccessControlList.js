
var setImmediateShim = setTimeout
// browser shim
if(typeof setImmediate !== 'undefined') {
  setImmediateShim = setImmediate
}

//   var perm = {
//     acl: {
//       roles: ['emea'],
//       control: 'required',
//       actions: 'rw',
//       conditions: [{
//           attributes: {
//             'region': 'emea'
//           }
//         }
//       ]
//     }
//   }
var _        = require('lodash')
var OTParser = require('object-tree')

function AccessControlList(conf) {

  if(!conf) { throw new Error ('missing configuration') }
  if(!conf.roles) { throw new Error('roles is required') }
  if(!_.isArray(conf.roles)) { throw new Error('roles should be a string array') }

  this._roles = conf.roles
  this._name = conf.name || JSON.stringify(conf.roles)
  this._hard = conf.hard || false

  if(!conf.control) { throw new Error('control is required') }
  this._control = conf.control

  // create a map for O(1) speed
  this._actions = {}
  if(conf.actions && _.isArray(conf.actions)) {
    for(var i = 0 ; i < conf.actions.length ; i++) {
      this._actions[conf.actions[i]] = true
    }
  }

  if(conf.filters) {
    this._filters = conf.filters
  }

  this._conditions = conf.conditions || []

  this._objectParser = new OTParser()
}

AccessControlList.prototype.shouldApply = function(obj, action) {
  var shouldApply = {
    ok: true
  }

  if(!this._actionMatch(action)) {
    shouldApply.ok = false
    shouldApply.reason = 'action does not match'
  }

  return shouldApply
}

AccessControlList.prototype._actionMatch = function(intendedAction) {
  return this._actions[intendedAction] === true
}

/**
 * returns:
 * - obj.ok=true if the rule should apply and the conditions match the context
 * - obj.ok=false if the rule should apply and the conditions don't match the context (access denied)
 * - obj.ok=undefined if the conditions don't match the object (rule should not apply)
 */
AccessControlList.prototype._conditionsMatch = function(obj, context) {
  var totalMatch = {
    ok: true
  }
  for(var i = 0 ; i < this._conditions.length ; i++) {
    var condition = this._conditions[i]
    var match = this._conditionMatch(condition, obj, context)
    if(match.ok === undefined) {
      totalMatch.ok = undefined
    } else if(match.ok === false && totalMatch.ok !== undefined) {
      totalMatch.ok = false
      if(match.reason) {
        totalMatch.reason = match.reason
      } else {
        totalMatch.reason = 'Condition #'+i+' does not match ==> '+ JSON.stringify(condition)
      }
    }

    if(match.inherit) {
      totalMatch.inherit = totalMatch.inherit || []
      totalMatch.inherit = totalMatch.inherit.concat(match.inherit)
    }
  }
  return totalMatch
}

AccessControlList.prototype._filter = function(obj) {
  if(this._filters) {
    var filters = []
    for(var attr in this._filters) {
      var filter = this._applyFilter(this._filters[attr], obj, attr)

      filters.push(filter)
    }
    return filters
  }

}

AccessControlList.prototype._applyFilter = function(filter, obj, attribute) {
  var filterResult = {}
  filterResult.attribute = attribute
  if(!filter) {
    filterResult.access = 'denied'
    filterResult.originalValue = obj[attribute]
  } else if(typeof filter === 'function') {
    filterResult.access = 'partial'
    filterResult.originalValue = obj[attribute]
    filterResult.filteredValue = filter(obj[attribute])
  } else if(_.isNumber(filter)) {
    if(_.isString(obj[attribute])) {
      filterResult.access = 'partial'
      filterResult.originalValue = obj[attribute]
      var fullMask = filterResult.originalValue.replace(/./g, '*')
      var maskedValue
      if(filter > 0) {
        // N = filter
        // mask all but the 'N' first characters
        maskedValue = filterResult.originalValue.substr(0, filter)
        if(fullMask.length > filter) {
          maskedValue += fullMask.substr(filter)
        }
      } else if(filter < 0) {
        // N = filter
        // mask all but the 'N' last characters
        maskedValue = filterResult.originalValue.substr(filter)
        if(fullMask.length > (-filter)) {
          maskedValue = fullMask.substr(0, fullMask.length + filter) + maskedValue
        }
      }
      filterResult.filteredValue = maskedValue
    } else {
      filterResult.access = 'denied'
      if(!filter) {
        filterResult.reason = 'trying to apply a replace filter on a falsy value'
      } else {
        filterResult.reason = 'trying to apply a replace filter on a value that is not a string'
      }
      filterResult.originalValue = obj[attribute]
      console.warn('Denying access to field ['+attribute+'].', filterResult.reason)
    }
  } else {
    throw new Error('unsupported filter', filter)
  }
  return filterResult

}

AccessControlList.prototype._conditionMatch = function(condition, obj, context) {
  var match = {ok: true}
  if(condition.attributes) {

    for(var attr in condition.attributes) {

      if(condition.attributes.hasOwnProperty(attr)) {
        var expectedValue = condition.attributes[attr]
        var actualValue = this._objectParser.lookup(attr, obj)
        if(this._objectParser.isTemplate(expectedValue)) {
          // Check to see if this is a NOT template. This will happen if it starts with {!
          // In order for the template to work replace the {! with { and set a flag that
          // we are inverting the following logic
          var mustNotExist = false;
          if(expectedValue.indexOf('{!') === 0) {
            mustNotExist = true;
            expectedValue = '{' + expectedValue.substr(2);
          }
          expectedValue = this._objectParser.lookupTemplate(expectedValue, context);
          if(!_.isArray(actualValue)) {
            actualValue = [actualValue];
          }
          if(mustNotExist) {
            if (~actualValue.indexOf(expectedValue)) {
              match.ok = false;
              match.reason = 'Attr [' + attr + '] should not be [' + expectedValue + '] but is in [' + actualValue + ']';
            }
          } else {
            if (!~actualValue.indexOf(expectedValue)) {
              match.ok = false;
              match.reason = 'Attr [' + attr + '] should be [' + expectedValue + '] but is not in [' + actualValue + ']';
            }
          }
        } else if(expectedValue === null && (actualValue === undefined || actualValue === null)) {
          match.reason = 'falsy value expected';
        } else if(actualValue !== expectedValue) {
          match.ok = undefined // this ACL should not apply to this object
          match.reason = 'Condition do not apply. Attr ['+attr+'] should be ['+expectedValue+'] but is ['+actualValue+']'
          return match
        }
      }
    }

  } else if(/^\{(.+\/){0,2}.*::.*\}$/.test(condition)) {
    // match {-/-/foobar::path.to.attr} or {-/foobar::path.to.attr} etc.

    var data = condition.slice(1, condition.length-1).split('::')
    var referencedId = this._objectParser.lookup(data[1], obj)

    var typeData = data[0].split('/')

    if(!referencedId) {
      // shortcut to denial if the reference does not exist, we cannot inherit its permissions
      match.ok = false
      match.reason = 'Authorization should be inherited from field ['+data[1]+'] but the field is falsy'
      return match
    } else {
      match.inherit = match.inherit || []
      var inheritance = {
        entity: {
        },
        id: referencedId
      }
      if(typeData[2]) {
        inheritance.entity.zone = typeData[0]
        inheritance.entity.base = typeData[1]
        inheritance.entity.name = typeData[2]
      } else if(typeData[1] && typeData[0] !== '-') {
        inheritance.entity.base = typeData[0]
        inheritance.entity.name = typeData[1]
      } else {
        inheritance.entity.name = typeData[0]
      }
      match.inherit.push(inheritance)
    }
  }
  return match
}

AccessControlList.prototype.authorize = function(obj, action, roles, context, callback) {
  var authorize = false
  var reason = ''
  var inherit = []
  var shouldApply = this.shouldApply(obj, action)
  var filters = null
  var hard = this._hard

  if(shouldApply.ok) {

    var conditionsMatch = this._conditionsMatch(obj, context)
    if(conditionsMatch.inherit) {
      inherit = inherit.concat(conditionsMatch.inherit)
    }

    if(conditionsMatch.ok === false) {

      authorize = false
      reason    = conditionsMatch.reason

    } else if(conditionsMatch.ok === true) {
      var rolesMatch = this._rolesMatch(this._roles, roles)
      authorize = rolesMatch.ok
      reason    = rolesMatch.reason

    } else {
      // conditions say this ACL does not apply
      authorize = true
      reason    = conditionsMatch.reason || 'ACL conditions do not apply'
    }

  } else {
    reason    = shouldApply.reason
    authorize = true
  }

  if(!authorize) {
    filters = this._filter(obj)
    if(this.control() === 'filter') {
      // filters allways pass but add a filter
      authorize = true
      reason = 'applying filter because the roles do not match'
    }
  }

  setImmediateShim(function() {
    callback(undefined, {authorize: authorize, reason: reason, inherit: inherit, filters: filters, hard: hard})
  })
}

AccessControlList.prototype._rolesMatch = function(expectedRoles, actualRoles) {
  var rolesMatch = {ok: true}
  var missingRoles = []
  if(expectedRoles && expectedRoles.length > 0) {

    // TODO: optimize this O(N square) into at least a O(N)
    for(var i = 0 ; i < expectedRoles.length ; i++) {
      var match = false
      if(actualRoles) {
        for(var j = 0 ; j < actualRoles.length ; j++) {
          if(actualRoles[j] === expectedRoles[i]) {
            match = true
            break
          }
        }
      }
      if(!match) {
        missingRoles.push(expectedRoles[i])
      }
    }
  }

  if(missingRoles.length > 0) {

    rolesMatch.ok = false
    rolesMatch.reason = 'expected roles ' + JSON.stringify(expectedRoles) +
      ' but got roles ' + JSON.stringify(actualRoles) +
      '. missing roles ' + JSON.stringify(missingRoles)
  } else if(rolesMatch.ok) {
    rolesMatch.reason = 'roles match as expected: ' + expectedRoles.join(',')
  }

  return rolesMatch
}

AccessControlList.prototype.control = function() {
  return this._control
}

AccessControlList.prototype.name = function() {
  return this._name
}

AccessControlList.prototype.hard = function() {
  return this._hard
}

AccessControlList.prototype.toString = function() {
  return 'ACL::' + this._name
}

module.exports = AccessControlList
