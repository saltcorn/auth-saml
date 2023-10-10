const SamlStrategy = require("passport-saml").Strategy;
const User = require("@saltcorn/data/models/user");
const Workflow = require("@saltcorn/data/models/workflow");
const Form = require("@saltcorn/data/models/form");
const File = require("@saltcorn/data/models/file");
const { readFileSync } = require("fs");
const { getState } = require("@saltcorn/data/db/state");

let strategy = null;

const keysAndCerts = ({
  cert,
  privateKey,
  decryptionPvk,
  decryptionCert,
  signingCert,
}) => {
  const result = {};
  if (cert) result.cert = readFileSync(cert, "latin1");
  if (privateKey) result.privateKey = readFileSync(privateKey, "latin1");
  if (decryptionPvk)
    result.decryptionPvk = readFileSync(decryptionPvk, "latin1");
  if (decryptionCert)
    result.decryptionCert = readFileSync(decryptionCert, "latin1");
  if (signingCert) result.signingCert = readFileSync(signingCert, "latin1");
  return result;
};

const authentication = (config) => {
  strategy = new SamlStrategy(
    {
      callbackUrl: config.callbackUrl || "",
      entryPoint: config.entryPoint || "",
      issuer: config.issuer || "",
      ...(config.audience ? { audience: config.audience } : {}),
      ...keysAndCerts(config),
      forceAuthn: true,
    },
    (profile, done) => {
      // login verify
      const email = profile.nameID;
      User.findOrCreateByAttribute("samlId", email, { email }).then((u) => {
        if (!u) return done(null, false);
        return done(null, u.session_object);
      });
    },
    // the stategy uses 'forceAuthn' to login every time
    // no single logout for now
    (profile, done) => {}
  );

  return {
    saml: {
      label: config.label || "SAML",
      setsUserAttribute: "saml2Id",
      strategy,
    },
  };
};

const routes = (config) => {
  return [
    {
      url: "/metadata",
      method: "get",
      callback: async ({ req, res }) => {
        try {
          if (!strategy) throw new Error("SAML strategy not initialized");
          const metadata = strategy.generateServiceProviderMetadata(
            config.decryptionCert
              ? readFileSync(config.decryptionCert, "latin1")
              : null,
            config.signingCert
              ? readFileSync(config.signingCert, "latin1")
              : null
          );
          res.type("application/xml");
          res.status(200).send(metadata);
        } catch (error) {
          getState().log(2, `GET /metadata: '${error.message}'`);
          return res.status(500).send(error.message);
        }
      },
    },
  ];
};

const configuration_workflow = () => {
  return new Workflow({
    steps: [
      {
        name: "SAML Configuration",
        form: async () => {
          const certs = await File.find({
            folder: "/certs",
            mime_super: "application",
            mime_sub: "x-x509-ca-cert",
          });
          return new Form({
            blurb:
              "These are configuration parameters for the SAML authentication module.</br>" +
              "To select certificates and private keys, please create a '/certs' folder at the root of your saltcorn file system " +
              "and upload the files there. " +
              "The MIME type must always be 'application/x-x509-ca-cert'.",
            fields: [
              {
                name: "callbackUrl",
                label: "Callback URL",
                sublabel:
                  "full callback URL e.g. https://www.saltcorn.com/auth/saml/callback",
                type: "String",
                required: true,
              },
              {
                name: "entryPoint",
                label: "Entry Point URL",
                sublabel:
                  "identity provider entrypoint (is required to be spec-compliant when the request is signed)",
                type: "String",
                required: true,
              },
              {
                name: "issuer",
                label: "Issuer",
                sublabel: "issuer string to supply to identity provider",
                type: "String",
                required: true,
              },
              {
                name: "audience",
                label: "Audience",
                sublabel:
                  "expected saml response Audience, defaults to value of Issuer (if false, Audience won't be verified)",
                type: "String",
              },
              {
                label: "Identity Provider Certificate",
                name: "cert",
                sublabel:
                  "the IDP's public signing certificate will be used to validate the signatures of the incoming SAML Responses, " +
                  "see <a href='https://github.com/node-saml/node-saml#security-and-signatures' target='_blank' >Security and signatures</a>",
                type: "String",
                attributes: {
                  options: certs.map((c) => c.location),
                },
              },
              {
                name: "decryptionPvk",
                label: "Service Provider Decryption Private Key",
                sublabel:
                  "optional private key that will be used to attempt to decrypt any encrypted assertions that are received",
                type: "String",
                attributes: {
                  options: certs.map((c) => c.location),
                },
              },
              {
                name: "decryptionCert",
                label: "Service Provider Decryption Certificate",
                sublabel:
                  "public certificate matching the 'Service Provider Decryption Private Key (decryptionPvk)', " +
                  "it is required if the strategy is configured with a decryptionPvk",
                type: "String",
                attributes: {
                  options: certs.map((c) => c.location),
                },
              },
              {
                name: "privateKey",
                label: "Service Provider Signing Private Key",
                sublabel:
                  "To sign authentication requests, private key needs to be provide in the PEM format",
                type: "String",
                attributes: {
                  options: certs.map((c) => c.location),
                },
              },
              {
                label: "Service Provider Signing Certificate",
                name: "signingCert",
                sublabel:
                  "The signingCert argument should be a public certificate matching the 'Service Provider Signing Private Key' (privateKey) " +
                  "and is required if the strategy is configured with a privateKey",
                type: "String",
                attributes: {
                  options: certs.map((c) => c.location),
                },
              },
            ],
          });
        },
      },
    ],
  });
};

module.exports = {
  authentication,
  routes,
  configuration_workflow,
  sc_plugin_api_version: 1,
};
