

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

  if (conf.inherit) {
    this._inherit = conf.inherit
  }

  this._objectParser = new OTParser()
}

AccessControlList.prototype.shouldApplyInherited = function(obj, action, roles, context) {
  var inheritApply = {
    ok: true
  }
  var self = this
  if (self._inherit && context.inherit$) {
    var skip = _.any(self._inherit.allow, function(allow) {
      var rolesMatch = self._rolesMatch(allow.roles, roles)
      if (rolesMatch.ok) {
        var entityMatch = _.findWhere(allow.entities, context.inherit$.entityDef)
        if (entityMatch) {
          return _.all(allow.conditions, function(condition) {
            var match = self._conditionMatch(condition, context.inherit$.entity, action, context)
            return (match.ok === true)
          })
        }
        else {
          return false
        }
      }
      else {
        return false
      }
    })
    if (skip) {
      inheritApply.ok = false
      inheritApply.reason = 'inherit pass through'
    }
  }
  return inheritApply
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
AccessControlList.prototype._conditionsMatch = function(obj, action, context) {
  var totalMatch = {
    ok: true
  }
  for(var i = 0 ; i < this._conditions.length ; i++) {
    var condition = this._conditions[i]
    var match = this._conditionMatch(condition, obj, action, context)
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

  // foo: false => foo denied
  if(!filter) {
    filterResult.access = 'denied'
    filterResult.originalValue = obj[attribute]
  } else
  // foo: [...] => foo denied if (new) value is in specified array of values
  // used with write operations to disallow certain values to be set on a field
  // doesn't make much sense for read operations, but if used with reads it will
  //  stop certain values from being returned
  if(_.isArray(filter)) {
    filterResult.originalValue = obj[attribute]
    if (~filter.indexOf(obj[attribute])) {
      filterResult.access = 'denied'
    }
    else {
      // if value is not in specified array of values, allow it through
    }
  } else
  // custom filter function
  // only works for read operations, replaces original field value with
  //  the value returned from the custom filtration function
  // when used with write operations the returned value has no effect
  //  and access to field will be always denied
  if(_.isFunction(filter)) {
    filterResult.access = 'partial'
    filterResult.originalValue = obj[attribute]
    filterResult.filteredValue = filter(obj[attribute])
  } else
  // "mask" filter for read operations
  // if positive will replace first N characters with *
  // if negative will replace last N characters with *
  if(_.isNumber(filter)) {
    // only works with strings, for non-string values simply denies access
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
      if (typeof console !== 'undefined') {
        console.warn('Denying access to field ['+attribute+'].', filterResult.reason)
      }
    }
  } else {
    throw new Error('unsupported filter', filter)
  }

  return filterResult

}

AccessControlList.prototype._conditionMatch = function(condition, obj, action, context) {
  var match = {ok: true}

  // at least one common element between expected and actual
  var oneMatch = function(expected, actual) {
    if (_.isUndefined(expected) || _.isUndefined(actual)) {
      return false
    }

    expected = _.isArray(expected) ? expected : [expected]
    actual = _.isArray(actual) ? actual : [actual]

    for (var i=0; i<expected.length; i++) {
      for (var j=0; j<actual.length; j++) {
        if (expected[i] === actual[j]) {
          return true
        }
      }
    }
    return false
  }

  if(condition.attributes) {

    for(var attr in condition.attributes) {

      if(condition.attributes.hasOwnProperty(attr)) {

        var areEqual
        var invertedCondition = false

        var expectedValue = condition.attributes[attr]

        if(attr.indexOf('!') === 0) {
          attr = attr.slice(1)
          invertedCondition = true
        }

        var actualValue
        if (obj.original$) {
          actualValue = this._objectParser.lookup(attr, obj.original$)
        }
        else {
          actualValue = this._objectParser.lookup(attr, obj)
        }

        if(this._objectParser.isTemplate(expectedValue)) {
          // Check to see if this is a NOT template. This will happen if it starts with {!
          // In order for the template to work replace the {! with { and set a flag that
          // we are inverting the following logic
          if(expectedValue.indexOf('{!') === 0) {
            invertedCondition = true
            expectedValue = '{' + expectedValue.substr(2)
          }
          expectedValue = this._objectParser.lookupTemplate(expectedValue, context)

          areEqual = oneMatch(expectedValue, actualValue)

          if(invertedCondition) {
            if (areEqual) {
              match.ok = false
              match.reason = 'Attr [' + attr + '] should not be [' + actualValue + '] but is in [' + expectedValue + ']'
            }
          } else {
            if (!areEqual) {
              match.ok = false
              match.reason = 'Attr [' + attr + '] should be [' + actualValue + '] but is not in [' + expectedValue + ']'
            }
          }
        } else {
          if (expectedValue === null) { // special handling when expecting value null (literal)
            var bothNull = (actualValue === undefined || actualValue === null)
            if (invertedCondition) { // inverted
              if (bothNull) { // left null, right null
                // TODO: review
                // irregular behaviour here when using the bang on the attr name and literal null as the expectected value
                // returns false here if actual value is null when normally it should return undefined
                match.ok = false
                match.reason = 'Condition do not apply. Truthy value expected for attr ['+attr+'] but got ['+actualValue+']'
                return match
              }
              else {
                // if the condition matches then match.ok should preserve its current value
              }
            }
            else { // normal
              if (!bothNull) { // left null, right !null
                // TODO: review
                // figure out why we're returning false on the inverted path above
                // might need to return false here as well
                match.ok = undefined // this ACL should not apply to this object
                match.reason = 'Condition do not apply. Attr ['+attr+'] should be ['+expectedValue+'] but is ['+actualValue+']'
                return match
              }
              else { // left null, right null
                // nothing to do here. condition matches, match.ok preserves its current value
                // left overs from v0.5.2:
                //match.reason = 'falsy value expected'
              }
            }
          }
          else {
            areEqual = oneMatch(expectedValue, actualValue)

            if (invertedCondition) { // inverted
              if (areEqual) {
                // !!! not handled in v0.5.2
                match.ok = undefined
                match.reason = 'Condition do not apply. Attr ['+attr+'] should *NOT* be ['+expectedValue+'] but is ['+actualValue+']'
                return match
              }
              else {
                // if the condition matches then match.ok should preserve its current value
                // !!! removed:
                //match.ok = true
                // as match.ok should is initialized with true and should only be set to false or undefined while evaluating attrs
                // more left overs from v0.5.2:
                //match.reason = 'Condition match. Attr ['+attr+'] should *NOT* be ['+expectedValue+'] and is ['+actualValue+']'
              }
            }
            else { // normal
              if (!areEqual) {
                match.ok = undefined // this ACL should not apply to this object
                match.reason = 'Condition do not apply. Attr ['+attr+'] should be ['+expectedValue+'] but is ['+actualValue+']'
                return match
              }
              else {
                // nothing to do here. condition matches, match.ok preserves its current value
              }
            }
          }
        }
      }
    }
  } else if (condition.fn) {

    var result = condition.fn(obj, context)

    if (result.ok !== true) {
      match.ok = result.ok
      match.reason = result.reason
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
  var missing = null
  if(shouldApply.ok) {


    var conditionsMatch = this._conditionsMatch(obj, action, context)

    if(conditionsMatch.inherit) {
      inherit = inherit.concat(conditionsMatch.inherit)
    }

    if(conditionsMatch.ok === false) {

      reason    = conditionsMatch.reason
      if(this.control() === 'filter') {
        reason = 'skipping filter because the conditions do not match'
        authorize = true
      } else {
        authorize = false
      }

    } else if(conditionsMatch.ok === true) {
      var rolesMatch = this._rolesMatch(this._roles, roles)

      reason    = rolesMatch.reason
      missing   = rolesMatch.missing
      if(!rolesMatch.ok && this.control() === 'filter') {
        reason = 'applying filter because the roles do not match'
        filters   = this._filter(obj)
        authorize = true
      } else {
        authorize = rolesMatch.ok
      }

    } else {
      // conditions say this ACL does not apply
      if(this.control() === 'sufficient') {
        authorize = false
      } else {
        authorize = true
      }
      reason    = conditionsMatch.reason || 'ACL conditions do not apply'
    }

  } else {
    reason    = shouldApply.reason
    authorize = true
  }

  setImmediateShim(function() {
    callback(undefined, {
      authorize: authorize,
      reason: reason,
      inherit: inherit,
      filters: filters,
      hard: hard,
      missingRoles: missing
    })
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
    rolesMatch.missing = missingRoles
    rolesMatch.reason = 'expected roles ' + JSON.stringify(expectedRoles) +
      ' but got roles ' + JSON.stringify(actualRoles) +
      '. missing roles ' + JSON.stringify(missingRoles)
  } else if(rolesMatch.ok) {
    rolesMatch.reason = 'roles match as expected: ' + expectedRoles.join(',')
  }

  return rolesMatch
}

AccessControlList.prototype.roles = function() {
  return this._roles
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
