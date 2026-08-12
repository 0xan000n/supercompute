import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The workspace packages ship TypeScript source, so Next must compile them.
  transpilePackages: ["@ctn/client", "@ctn/protocol"],
  typedRoutes: false,
};

export default nextConfig;
