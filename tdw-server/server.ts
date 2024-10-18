import { Elysia } from 'elysia';
import { createSigner, createDID, DIDLog, resolveDID } from 'trustdidweb-ts';
import { generateEd25519VerificationMethod, generateX25519VerificationMethod } from 'trustdidweb-ts/src/cryptography';
import { PrismaClient } from '@prisma/client';

const DOMAIN = process.env.DOMAIN;
const db = new PrismaClient();

const app = new Elysia()
  .get('/', () => 'Hello world!')
  .get('/create', async () => {
    const authKey = await generateEd25519VerificationMethod('authentication');
    const agreementKey = await generateX25519VerificationMethod('keyAgreement');

    const result = await createDID({
      domain: DOMAIN,
      signer: createSigner(authKey),
      updateKeys: [
        authKey.publicKeyMultibase,
        agreementKey.publicKeyMultibase
      ],
      verificationMethods: [authKey, agreementKey],
      created: new Date(),
    });

    await db.user.create({
      data: {
        did: result.did,
        doc: result.doc,
        log: result.log,
        meta: result.meta,
      },
    });

    return {
      public: result,
      private: {
        authKey,
        agreementKey
      }
    };
  })
  .get('/get/:id', async ({ params: { id } }) => {
    console.log(`Resolving ${id}...`);
    try {
      const current = await db.user.findUnique({ where: { did: id } });

      if (!current) {
        throw new Error(`User with DID ${id} not found`);
      }

      const logEntries: DIDLog = current.log;
      const { doc, meta } = await resolveDID(logEntries);

      return { doc, meta };
    } catch (e) {
      console.error(e);
      throw new Error(`Failed to resolve DID`);
    }
  })
  .listen(8000);

console.log(
  `🔍 Publication server is running at on port ${app.server?.port}...`
);
