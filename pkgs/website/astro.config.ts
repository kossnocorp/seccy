import cloudflare from "@astrojs/cloudflare";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://seccy.fiy",

  vite: {
    plugins: [tailwindcss()],
  },

  adapter: cloudflare(),
});
