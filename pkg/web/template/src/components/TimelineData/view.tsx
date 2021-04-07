import React from 'react';

import { Panel, Timeline, Tooltip, Whisper } from 'rsuite';

import 'rsuite/lib/Timeline/styles';
import 'rsuite/lib/Tooltip/styles';
import './index.css';

import { ReportModelState, ErrorStatus } from '@/models/report';
import { BuilderJsxFromModel } from '@/data/RenderData';

const Status = (props: ReportModelState) => {
  return (
    <Whisper placement={'top'} trigger={'hover'}
             speaker={<Tooltip>{props.desc}</Tooltip>}>
      <div className={`dot ${props.status === ErrorStatus ? 'error' : ''}`} />
    </Whisper>
  );
};

const Item = (props: ReportModelState) => {
  const data = BuilderJsxFromModel(props);
  return (
    <Timeline.Item dot={<Status {...props} key={props.name}/>}>
      <div className={'meta-item'}>
        <span className={'time'}> {props.time}</span>
        <span className={'name'}> {props.name}</span>
      </div>
      {data}
    </Timeline.Item>
  );
};

const TimelineData = (props: ReportModelState) => {
  const dataListItems = props.dataList
    ? props.dataList.map((item) => <Item {...item} key={item.name} />)
    : <div>数据为空</div>;
  return (
    <Panel header={props.name} className={"footer"}>
      <Timeline endless={true}>{dataListItems}</Timeline>
    </Panel>
  );
};

export default TimelineData;
