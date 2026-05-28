import "./globals.css";

export const metadata = {
  title: "heiLLMpot Dashboard",
  description: "Live orchestrator telemetry for heiLLMpot"
};

export default function RootLayout({children}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
