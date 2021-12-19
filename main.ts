import { sample } from "https://deno.land/std@0.118.0/collections/mod.ts";
import {
  json,
  serve,
  validateRequest,
} from "https://deno.land/x/sift@0.4.2/mod.ts";
import nacl from "https://cdn.skypack.dev/tweetnacl@v1.0.3";
import { dongers } from "./dongers.ts";

serve({ "/": mainRequestHandler });

async function mainRequestHandler(request: Request) {
  const { error } = await validateRequest(request, {
    POST: {
      headers: ["X-Signature-Ed25519", "X-Signature-Timestamp"],
    },
  });
  if (error) {
    console.info("Invalid request", { url: request.url, body: request.body });
    return json({ error: error.message }, { status: error.status });
  }

  const { valid, body } = await verifySignature(request);
  if (!valid) {
    console.info("Unsigned request", { url: request.url, body: request.body });
    return json(
      { error: "Unsigned request" },
      {
        status: 401,
      },
    );
  }

  const { type = 0, data } = JSON.parse(body);
  console.info("Valid request", { type, data });
  // Discord performs type 1 Ping interactions to test our application.
  if (type === 1) {
    return json({
      // Response type 1: Pong
      type: 1,
    });
  }

  // Type 2 in a request is an ApplicationCommand interaction.
  // It implies that a user has issued a command.
  if (type === 2) {
    const categoryOption: { value: keyof typeof dongers } = data.options?.find((
      option: { name: string },
    ) => option.name === "category");

    const dongerArray = dongers[categoryOption?.value] ||
      Object.values(dongers).flat();

    return json({
      // Type 4 reponds with the below message retaining the user's
      // input at the top.
      type: 4,
      data: {
        content: sample(dongerArray),
      },
    });
  }

  // We will return a bad request error as a valid Discord request
  // shouldn't reach here.
  console.info("Bad request", { url: request.url, body: request.body });
  return json({ error: "Bad request" }, { status: 400 });
}

async function verifySignature(
  request: Request,
): Promise<{ valid: boolean; body: string }> {
  const PUBLIC_KEY = Deno.env.get("DISCORD_PUBLIC_KEY")!;
  // Discord sends these headers with every request.
  const signature = request.headers.get("X-Signature-Ed25519")!;
  const timestamp = request.headers.get("X-Signature-Timestamp")!;
  const body = await request.text();
  const valid = nacl.sign.detached.verify(
    new TextEncoder().encode(timestamp + body),
    hexToUint8Array(signature),
    hexToUint8Array(PUBLIC_KEY),
  );

  return { valid, body };
}

function hexToUint8Array(hex: string) {
  return new Uint8Array(hex.match(/.{1,2}/g)!.map((val) => parseInt(val, 16)));
}
