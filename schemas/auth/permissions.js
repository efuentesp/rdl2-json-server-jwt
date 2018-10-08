const joi = require("joi");

module.exports = joi.object().keys({
  code: joi
    .string()
    .trim()
    .max(64)
    .regex(/^(([A-Z0-9_])+|[*]):(([A-Z0-9_])+|[*])$/, "permission")
    .required(),
  description: joi
    .string()
    .trim()
    .max(64)
    .required()
});
