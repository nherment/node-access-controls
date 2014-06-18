
var require = function(module) {
    if(/AccessControlList/.test(module)) {
        return AccessControls.ACL
    } else if(/AccessControlProcedure/.test(module)) {
        return AccessControls
    } else if(module === 'assert') {
        return chai.assert
    } else {
        throw new Error('Could not find module ' + module)
    }
};
