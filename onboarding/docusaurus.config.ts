import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";

const UPSTREAM_REPO = "zcash/sapling-crypto";
const UPSTREAM_REF = "0.7.0";
const FORK_REPO = "dannywillems/sapling-crypto";
const FORK_BRANCH = "onboarding";

const config: Config = {
  title: "Sapling-crypto onboarding",
  tagline:
    "A graduate-level walk through the Zcash Sapling cryptography crate.",
  favicon: "img/favicon.ico",

  future: {
    v4: true,
  },

  url: "https://dannywillems.github.io",
  baseUrl: "/sapling-crypto/",

  organizationName: "dannywillems",
  projectName: "sapling-crypto",
  trailingSlash: false,

  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  markdown: {
    format: "detect",
    hooks: {
      onBrokenMarkdownLinks: "throw",
    },
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          routeBasePath: "/",
          remarkPlugins: [remarkMath],
          rehypePlugins: [rehypeKatex],
          editUrl: `https://github.com/${FORK_REPO}/edit/${FORK_BRANCH}/onboarding/`,
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  stylesheets: [
    {
      href: "https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css",
      type: "text/css",
      integrity:
        "sha384-nB0miv6/jRmo5EGIE6RDQE0etf4GvjBR1bkf4pcUk2TprLGa0k7/rJkRnCu6WSt6",
      crossorigin: "anonymous",
    },
  ],

  themes: [
    [
      "@easyops-cn/docusaurus-search-local",
      {
        hashed: true,
        indexBlog: false,
        indexDocs: true,
        indexPages: true,
        language: ["en"],
        highlightSearchTermsOnTargetPage: true,
      },
    ],
    "docusaurus-theme-github-codeblock",
  ],

  themeConfig: {
    announcementBar: {
      id: "ai-generated-disclaimer",
      isCloseable: false,
      backgroundColor: "#fef3c7",
      textColor: "#78350f",
      content:
        'This site is automatically generated using Claude Code. Errors may have been introduced. The code is the law, always refer to the source in the <a href="https://github.com/zcash/sapling-crypto">zcash/sapling-crypto</a> repository.',
    },
    colorMode: {
      respectPrefersColorScheme: true,
    },
    codeblock: {
      showGithubLink: true,
      githubLinkLabel: "View on GitHub",
    },
    navbar: {
      title: "sapling-crypto onboarding",
      items: [
        {
          type: "docSidebar",
          sidebarId: "docsSidebar",
          position: "left",
          label: "Course",
        },
        {
          href: `https://github.com/${UPSTREAM_REPO}/tree/${UPSTREAM_REF}`,
          label: `Upstream ${UPSTREAM_REF}`,
          position: "right",
        },
        {
          href: `https://github.com/${FORK_REPO}/tree/${FORK_BRANCH}`,
          label: "Edit this site",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Code",
          items: [
            {
              label: `Upstream (${UPSTREAM_REPO} @ ${UPSTREAM_REF})`,
              href: `https://github.com/${UPSTREAM_REPO}/tree/${UPSTREAM_REF}`,
            },
            {
              label: `This site (${FORK_REPO})`,
              href: `https://github.com/${FORK_REPO}/tree/${FORK_BRANCH}`,
            },
          ],
        },
        {
          title: "Authoritative specs",
          items: [
            {
              label: "Zcash Protocol Specification",
              href: "https://zips.z.cash/protocol/protocol.pdf",
            },
            {
              label: "ZIP 32 (HD key derivation)",
              href: "https://zips.z.cash/zip-0032",
            },
            {
              label: "ZIP 212 (note plaintext)",
              href: "https://zips.z.cash/zip-0212",
            },
            {
              label: "ZIP 216 (RedJubjub canonical encoding)",
              href: "https://zips.z.cash/zip-0216",
            },
          ],
        },
      ],
      copyright:
        "Course content licensed MIT/Apache-2.0 to match the upstream crate.",
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["rust", "bash", "toml", "json", "yaml", "diff"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
