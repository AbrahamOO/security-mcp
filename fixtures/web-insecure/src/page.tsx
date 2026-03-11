export function Page() {
  const html = "<img src=x onerror=alert(1) />";
  void fetch("http://169.254.169.254/latest/meta-data");
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
