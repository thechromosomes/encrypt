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

let DB_MOCKUP = [
  {
    ocpVersion: "2.0.1",
    action: "charge",
    requestId: "123456789",
    vinHash: "9a73bfc3ddb1e353f7fb2fcbf055255f347d206057e3601343337f006555afbd",
    vinActual: "VID:ABCdef12",
    chargingParameters: {
      maxPower: 7.4,
      chargingType: "AC",
      connectorType: "Type 2",
      startTime: "2023-07-20T10:00:00",
      endTime: "2023-07-20T14:00:00",
      chargingRateLimit: 5.0,
      maxCapacity: 50.0,
      chargingProfile: "normal",
      isReservation: true,
    },
  },
  {
    ocpVersion: "2.0.1",
    action: "charge",
    requestId: "987654321",
    vinHash: "c15e0cbeff8d0e1ad6858f03817b936e8a0fb7e9ad18357146f71ab29a19e364",
    vinActual: "VID:xyzGHI89",
    chargingParameters: {
      maxPower: 11.0,
      chargingType: "DC",
      connectorType: "CCS Combo",
      startTime: "2023-07-20T12:00:00",
      endTime: "2023-07-20T18:00:00",
      chargingRateLimit: 10.0,
      maxCapacity: 70.0,
      chargingProfile: "fast",
      isReservation: false,
    },
  },
  {
    ocpVersion: "2.0.1",
    action: "charge",
    requestId: "246813579",
    vinHash: "45e4662fc303e26f76d06e6960db3c69e26ec1e2dc9f3ab68a29300fc42c9bec",
    vinActual: "VID:pqrSTU34",
    chargingParameters: {
      maxPower: 3.6,
      chargingType: "AC",
      connectorType: "Type 1",
      startTime: "2023-07-20T09:00:00",
      endTime: "2023-07-20T15:00:00",
      chargingRateLimit: 2.0,
      maxCapacity: 40.0,
      chargingProfile: "slow",
      isReservation: true,
    },
  },
  {
    ocpVersion: "2.0.1",
    action: "charge",
    requestId: "135792468",
    vinHash: "c1851fe4dcb9c451017bf22a2d5604b2786f8105350e89f479d5ecd33e384ffb",
    vinActual: "VID:lmnOPQ56",
    chargingParameters: {
      maxPower: 22.0,
      chargingType: "DC",
      connectorType: "Tesla Supercharger",
      startTime: "2023-07-20T08:00:00",
      endTime: "2023-07-20T13:00:00",
      chargingRateLimit: 20.0,
      maxCapacity: 100.0,
      chargingProfile: "supercharge",
      isReservation: false,
    },
  },
  {
    ocpVersion: "2.0.1",
    action: "charge",
    requestId: "314159265",
    vinHash: "d8b5e5d775a21473788740452425b12e0ace1b771a93019e28f651712254cf6a",
    vinActual: "VID:uvwXYZ78",
    chargingParameters: {
      maxPower: 7.4,
      chargingType: "AC",
      connectorType: "Type 2",
      startTime: "2023-07-20T10:30:00",
      endTime: "2023-07-20T17:00:00",
      chargingRateLimit: 6.0,
      maxCapacity: 55.0,
      chargingProfile: "normal",
      isReservation: true,
    },
  },
];

function encryptData(data) {
  const hash = crypto.createHash("sha256");
  hash.update(JSON.stringify(data));
  const hashedData = hash.digest("hex");
  return hashedData;
}

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
    res.send("Error occurred", error);
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
   let givenVin = JSON.parse(decryptedData);
    let result;
    if (givenVin.vin) {
      let finalData = DB_MOCKUP.filter((elem) => elem.vinActual === givenVin.vin);

      if (finalData.length) {
        result = finalData[0].chargingParameters;
      } else {
        throw "Invalid ID";
      }
    }

    res.send({ decryptedData, result });
  } catch (error) {
    res.send("Error occurred");
  }
});

app.post("/on-way-encrypt", (req, res) => {
  try {
    const data = req.body.vehicleId;
    const encryptedData = encryptData(data);
    res.send({ encryptedData });
  } catch (error) {
    res.send("error occurred");
  }
});

app.post("/verify-on-way-encrypt", (req, res) => {
  try {
    const vehicleId = req.body.vehicleId;
    let finalData = DB_MOCKUP.filter((elem) => elem.vinHash === vehicleId);
    let result;

    if (finalData.length) {
      result = finalData[0].chargingParameters;
    } else {
      throw "Invalid ID";
    }

    res.status(200).send({
      result,
    });
  } catch (error) {
    res.status(500).send("Error occurred");
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
