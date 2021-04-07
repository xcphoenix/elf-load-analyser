import React from 'react';

import { Popover, Whisper } from 'rsuite';

import './index.css';
import 'rsuite/lib/Popover/styles';

const ListRender = (props: { items: Array<string>, kv?: boolean }) => {
  if (!props || props.items.length < 1) {
    return <div>没有数据</div>;
  }
  let items = props.items.map((item, idx) => {
    if (props.kv) {
      let idx = item.indexOf('=');
      let key = item.substring(0, idx), value = item.substring(idx, item.length);
      return (
        <div className={'list-item'} key={key}>
          <Whisper placement='top' trigger='click' speaker={
            <Popover title={key}><span>{value.substring(1, value.length)}</span></Popover>
          }>
            <span><b>{key}</b>{value}</span>
          </Whisper>
        </div>
      );
    }
    return <div className={'list-item'} key={idx}>{item}</div>;
  });
  return <div>{items}</div>;
};

export default ListRender;
