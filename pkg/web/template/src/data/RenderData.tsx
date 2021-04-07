/**
 * RenderData
 */
import React, { ReactElement } from 'react';
import { RenderContent, ReportModelState } from '@/models/report';
import MarkdownRender from '@/components/Markdown';
import ListRender from '@/components/List';
import TableRender from '@/components/Table';

export interface DataRender {
  GetType(): number

  Render(): ReactElement
}

class EmptyDataRender implements DataRender {
  private static instance: EmptyDataRender = new EmptyDataRender();

  private constructor() {
  }

  GetType(): number {
    return -1;
  }

  Render(): React.ReactElement {
    return <div>Invalid data type</div>;
  }

  static getInstance(): EmptyDataRender {
    return EmptyDataRender.instance;
  }
}

class MarkdownDataRender implements DataRender {
  data: string;

  constructor(data: string) {
    this.data = data;
  }

  GetType(): number {
    return 1;
  }

  Render(): React.ReactElement {
    return <MarkdownRender src={this.data} />;
  }
}

class ListDataRender implements DataRender {
  data: {
    kv?: boolean;
    items: Array<string>;
  };

  constructor(data: { kv?: boolean; items: Array<string>; }) {
    this.data = data;
  }

  GetType(): number {
    return 2;
  }

  Render(): React.ReactElement {
    return <ListRender items={this.data.items} kv={this.data.kv} />;
  }
}

class TableDataRender implements DataRender {
  data: {
    desc?: string;
    table: Array<any>;
  };

  constructor(data: { desc: string, table: Array<any> }) {
    this.data = data;
  }

  GetType(): number {
    return 3;
  }

  Render(): React.ReactElement {
    return <TableRender {...this.data} />;
  }
}

export function BuildRender(obj: RenderContent): DataRender {
  let { type, data } = obj;
  switch (type) {
    case 1:
      return new MarkdownDataRender(data);
    case 2:
      return new ListDataRender(data);
    case 3:
      return new TableDataRender(data);
  }
  console.log('invalid type: ' + type);
  return EmptyDataRender.getInstance();
}

export function BuilderJsxFromModel(model: ReportModelState): ReactElement {
  let content = model.data && model.data.length > 0 ?
    model.data.map((item, idx) => {
      return <div key={idx}>{BuildRender(item).Render()}</div>;
    })
    : <div>数据为空</div>;

  return <div>{content}</div>;
}
