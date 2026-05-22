"use client";

import { useEffect, useState } from "react";

interface Props {
  bio: string;
}

export default function Bio({ bio }: Props) {
  const [data, setData] = useState<string>(bio);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get("bio") || bio;
    setData(raw);
    localStorage.setItem("token", "abcd1234");
  }, [bio]);

  return <div dangerouslySetInnerHTML={{ __html: data }} />;
}
