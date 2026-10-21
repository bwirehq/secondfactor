import "reflect-metadata";
import {
  CanActivate,
  Controller,
  ExecutionContext,
  Get,
  Inject,
  Injectable,
  Module,
  UnauthorizedException,
  UseGuards,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { SecondFactorClient, type Identity } from "secondfactor-client";
import { readFileSync } from "node:fs";
// Populate this context from your existing authenticated session middleware.
// This example deliberately does not accept subject/session/proof claims from headers.
export interface TrustedRequest {
  primary?: { identity: Identity; accessProof: string };
}
@Injectable()
export class MFAGuard implements CanActivate {
  constructor(
    @Inject("SECONDFACTOR") private readonly client: SecondFactorClient,
  ) {}
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<TrustedRequest>();
    if (!req.primary)
      throw new UnauthorizedException("Primary session required");
    try {
      await this.client.validateProof(
        req.primary.identity,
        req.primary.accessProof,
        "access",
      );
      return true;
    } catch {
      throw new UnauthorizedException("MFA required");
    }
  }
}
@Controller()
class ExampleController {
  @Get("protected") @UseGuards(MFAGuard) protected() {
    return { message: "Primary session and MFA verified" };
  }
}
@Module({
  controllers: [ExampleController],
  providers: [
    MFAGuard,
    {
      provide: "SECONDFACTOR",
      useFactory: () =>
        new SecondFactorClient({
          baseURL: process.env.SECONDFACTOR_URL ?? "https://localhost:8443",
          audience: process.env.SECONDFACTOR_AUDIENCE ?? "secondfactor-local",
          application: process.env.SECONDFACTOR_APP ?? "demo",
          keyID: "app1",
          seed: Buffer.from(
            readFileSync(
              process.env.SECONDFACTOR_SEED_FILE ??
                "../../secrets/application.seed",
              "utf8",
            ).trim(),
            "base64",
          ),
        }),
    },
  ],
})
class ExampleModule {}
async function main() {
  const app = await NestFactory.create(ExampleModule);
  await app.listen(3000, "127.0.0.1");
}
void main();
