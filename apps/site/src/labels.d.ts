// Field and category names from the app's translations (see build.mjs).
declare module "virtual:labels" {
  type Names = { fieldLabels: Record<string, string>; categories: Record<string, string> };
  const labels: Record<"pt-BR" | "en" | "es", Names>;
  export default labels;
}
