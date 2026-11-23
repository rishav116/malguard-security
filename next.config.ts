import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  devIndicators: false,
  experimental: {
    cpus: 1,
  },
  async rewrites() {
    const backendUrl =
      process.env.FASTAPI_INTERNAL_URL ||
      process.env.NEXT_PUBLIC_FASTAPI_URL ||
      "http://127.0.0.1:8000";
    const cleanBackend = backendUrl.replace(/\/+$/, "");

    return [
      {
        source: "/api/v1/:path*",
        destination: `${cleanBackend}/api/v1/:path*`,
      },
      {
        source: "/health",
        destination: `${cleanBackend}/health`,
      },
    ];
  },
};

export default nextConfig;
