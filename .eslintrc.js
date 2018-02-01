module.exports = {
    "env": {
        "es6": true,
        "node": true
    },
    "plugins": [
        "hapi"
    ],
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion": 8,
        "sourceType": "module"
    },
    "rules": {
        "valid-jsdoc": [2],
        "no-multiple-empty-lines": [
          "error",
          { "max": 2, "maxBOF": 0, "maxEOF": 1 }
        ],
        "hapi/hapi-capitalize-modules": [
          "error"
        ],
        "no-unused-vars": [
            "error",
            { "vars": "all", "args": "none"}
        ],
        "indent": [
            "error",
            4
        ],
        "linebreak-style": [
            "error",
            "unix"
        ],
        "quotes": [
            "off",
            "double"
        ],
        "semi": [
            "warn",
            "never"
        ],
        "no-console": ["warn"],
    }
};
