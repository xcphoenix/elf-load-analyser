import React from 'react';

import Markdown from 'react-markdown';
import gfm from 'remark-gfm';

import './index.css';

const MarkdownRender = (props: { src: string }) => {
  return (
    <Markdown source={props.src}
              plugins={[gfm]}
              allowDangerousHtml={true} />
  );
};

export default MarkdownRender;
