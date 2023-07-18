"use strict";
const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const fs = require("fs");
const archiver = require("archiver");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

let privateKey = process.env.PRIVATE_KEY_PATH;
let publicKey = process.env.PUBLIC_KEY_PATH;

app.post("/encrypt", (req, res) => {
  try {
    function encryptData(data) {
      const encryptedData = crypto.publicEncrypt(publicKey, Buffer.from(data));
      return encryptedData.toString("base64");
    }
    const data = JSON.stringify(req.body.vehicleData);
    const encryptedData = encryptData(data);
    res.send({ encryptedData });
  } catch (error) {
    console.log(error)
    res.send("Error occurred");
  }
});

app.post("/decrypt", (req, res) => {
  try {
    function decryptData(encryptedData) {
      const decryptedData = crypto.privateDecrypt(
        privateKey,
        Buffer.from(encryptedData, "base64")
      );
      return decryptedData.toString();
    }
    const encryptedData = JSON.stringify(req.body.vehicleEncryptedData);
    const decryptedData = decryptData(encryptedData);
    res.send(decryptedData);
  } catch (error) {
    console.log(error)
    res.send("Error occurred");
  }
});

app.post("/on-way-encrypt", (req, res) => {
  try {
    function encryptData(data) {
      const hash = crypto.createHash("sha256");
      hash.update(JSON.stringify(data));
      const hashedData = hash.digest("hex");

      const encryptedData = crypto
        .publicEncrypt(publicKey, Buffer.from(hashedData, "hex"))
        .toString("hex");
      return encryptedData;
    }

    const data = req.body.vehicleData;
    const encryptedData = encryptData(data);
    res.send({ encryptedData });
  } catch (error) {
    res.send("error occurred");
  }
});

app.post("/verify-on-way-encrypt", (req, res) => {
  try {
    function verifyData(data, encryptedData) {
      try {
        const decryptedData = crypto
          .privateDecrypt(privateKey, Buffer.from(encryptedData, "hex"))
          .toString("hex");

        const computedHash = crypto
          .createHash("sha256")
          .update(JSON.stringify(data))
          .digest("hex");

        return computedHash === decryptedData;
      } catch (error) {
        return false; 
      }
    }

    const data = req.body.vehicleData;
    const encryptedData = req.body.encryptedData;

    const verified = verifyData(data, encryptedData);
    res.send({ verified });
  } catch (error) {
    res.send("Error occurred");
  }
});

// Generate RSA keys
app.get("/generate-keys", (req, res) => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    const publicKeyFilename = "public_key.pem";
    const privateKeyFilename = "private_key.pem";
    const zipFilename = "keys.zip";

    fs.writeFileSync(
      publicKeyFilename,
      publicKey.export({ format: "pem", type: "spki" })
    );
    fs.writeFileSync(
      privateKeyFilename,
      privateKey.export({ format: "pem", type: "pkcs8" })
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${zipFilename}"`
    );
    res.setHeader("Content-Type", "application/zip");

    const archive = archiver("zip");

    archive.on("error", (err) => {
      throw err;
    });

    archive.on("end", () => {
      fs.unlinkSync(publicKeyFilename);
      fs.unlinkSync(privateKeyFilename);
    });

    archive.pipe(res);
    archive.file(publicKeyFilename, { name: publicKeyFilename });
    archive.file(privateKeyFilename, { name: privateKeyFilename });
    archive.finalize();
  } catch (error) {
    res.status(500).send("Error generating and sending keys");
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
