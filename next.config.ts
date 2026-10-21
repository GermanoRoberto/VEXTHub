import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  experimental: {
    cpus: 1,
  },
  async redirects() {
    return [
      {
        source: '/dashboard/inventory',
        destination: '/dashboard/devices',
        permanent: true,
      },
      {
        source: '/dashboard/machines',
        destination: '/dashboard/devices',
        permanent: true,
      },
    ]
  },
  async rewrites() {
    return [
      {
        source: '/api/playbooks/:path*',
        destination: 'http://127.0.0.1:8000/api/playbooks/:path*',
      },
      {
        source: '/api/neural/:path*',
        destination: 'http://127.0.0.1:8000/api/neural/:path*',
      },
      {
        source: '/api/forensics/:path*',
        destination: 'http://127.0.0.1:8000/api/forensics/:path*',
      },
      {
        source: '/api/jobs/:path*',
        destination: 'http://127.0.0.1:8000/api/jobs/:path*',
      },
      {
        source: '/api/plugins/:path*',
        destination: 'http://127.0.0.1:8000/api/plugins/:path*',
      },
      {
        source: '/api/webhooks/:path*',
        destination: 'http://127.0.0.1:8000/api/webhooks/:path*',
      },
      {
        source: '/api/health',
        destination: 'http://127.0.0.1:8000/api/health',
      },
    ]
  },
};

export default nextConfig;
